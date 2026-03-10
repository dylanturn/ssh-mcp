"""Tests for ssh_mcp.connection — command execution and file transfer.

All SSH / paramiko calls are mocked so no real SSH server is required.
"""

from __future__ import annotations

import select
import threading
import time
from io import BytesIO
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from ssh_mcp.config import reset_settings
from ssh_mcp.connection import (
    CommandResult,
    ConnectionPool,
    execute_command,
    get_file,
    put_file,
    reset_pool,
)


@pytest.fixture(autouse=True)
def reset_state():
    reset_settings()
    reset_pool()
    yield
    reset_settings()
    reset_pool()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_client(stdout_data: bytes = b"out\n", stderr_data: bytes = b"", exit_code: int = 0):
    """Build a minimal mock paramiko SSHClient for a single exec_command call."""
    client = MagicMock()
    transport = MagicMock()
    transport.is_active.return_value = True
    client.get_transport.return_value = transport

    channel = MagicMock()
    channel.closed = False

    # Stateful closures so the mock responds correctly across many calls
    state = {"stdout_sent": False, "stderr_sent": False}

    pid_line = b"__SSH_MCP_PID__:12345\n"
    stderr_payload = pid_line + stderr_data

    def recv_ready_fn():
        return not state["stdout_sent"]

    def recv_stderr_ready_fn():
        return not state["stderr_sent"]

    def recv_fn(nbytes):
        if not state["stdout_sent"]:
            state["stdout_sent"] = True
            return stdout_data
        return b""

    def recv_stderr_fn(nbytes):
        if not state["stderr_sent"]:
            state["stderr_sent"] = True
            return stderr_payload
        return b""

    def exit_status_ready_fn():
        # Report done once both streams have been consumed
        return state["stdout_sent"] and state["stderr_sent"]

    channel.recv.side_effect = recv_fn
    channel.recv_stderr.side_effect = recv_stderr_fn
    channel.recv_ready.side_effect = recv_ready_fn
    channel.recv_stderr_ready.side_effect = recv_stderr_ready_fn
    channel.exit_status_ready.side_effect = exit_status_ready_fn
    channel.recv_exit_status.return_value = exit_code

    transport.open_session.return_value = channel
    return client, channel


# ---------------------------------------------------------------------------
# ConnectionPool tests
# ---------------------------------------------------------------------------


class TestConnectionPool:
    def test_acquire_opens_new_connection(self, monkeypatch):
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport

        pool = ConnectionPool(max_idle=2)
        with patch.object(pool, "_open_connection", return_value=mock_client) as mock_open:
            client = pool.acquire("10.0.0.1", 22, "user", None, None)
        mock_open.assert_called_once()
        assert client is mock_client

    def test_release_and_reuse(self, monkeypatch):
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport

        pool = ConnectionPool(max_idle=2)
        with patch.object(pool, "_open_connection", return_value=mock_client):
            c1 = pool.acquire("10.0.0.1", 22, "user", None, None)
            pool.release("10.0.0.1", 22, "user", c1)
            c2 = pool.acquire("10.0.0.1", 22, "user", None, None)
        # Should reuse the same object
        assert c2 is mock_client

    def test_stale_connection_discarded(self):
        stale = MagicMock()
        stale_transport = MagicMock()
        stale_transport.is_active.return_value = False
        stale.get_transport.return_value = stale_transport

        fresh = MagicMock()
        fresh_transport = MagicMock()
        fresh_transport.is_active.return_value = True
        fresh.get_transport.return_value = fresh_transport

        pool = ConnectionPool(max_idle=2)
        # Manually inject a stale connection into the pool bucket
        pool._pool[("10.0.0.1", 22, "user")] = [stale]

        with patch.object(pool, "_open_connection", return_value=fresh):
            client = pool.acquire("10.0.0.1", 22, "user", None, None)
        assert client is fresh

    def test_pool_respects_max_idle(self):
        pool = ConnectionPool(max_idle=1)
        c1 = MagicMock()
        c1.get_transport.return_value = MagicMock(is_active=lambda: True)
        c2 = MagicMock()
        c2.get_transport.return_value = MagicMock(is_active=lambda: True)

        pool.release("10.0.0.1", 22, "user", c1)
        pool.release("10.0.0.1", 22, "user", c2)  # should be closed, not pooled

        assert len(pool._pool[("10.0.0.1", 22, "user")]) == 1
        c2.close.assert_called_once()

    def test_close_all(self):
        pool = ConnectionPool(max_idle=5)
        c1 = MagicMock()
        c1.get_transport.return_value = MagicMock(is_active=lambda: True)
        pool._pool[("10.0.0.1", 22, "user")] = [c1]
        pool.close_all()
        c1.close.assert_called_once()
        assert pool._pool == {}


# ---------------------------------------------------------------------------
# execute_command tests
# ---------------------------------------------------------------------------


class TestExecuteCommand:
    def _run(self, stdout=b"out\n", stderr=b"", exit_code=0, **kwargs):
        """Helper: run execute_command against a mocked pool."""
        mock_client, channel = _make_mock_client(stdout, stderr, exit_code)
        pool = MagicMock()
        pool.acquire.return_value = mock_client

        with patch("select.select", return_value=([channel], [], [])):
            result = execute_command(
                host="10.0.0.1",
                username="user",
                command="echo hello",
                pool=pool,
                **kwargs,
            )
        return result

    def test_basic_success(self, monkeypatch):
        monkeypatch.setenv("SSH_MCP_ALLOWED_CIDRS", "10.0.0.0/8")
        result = self._run()
        assert result.exit_code == 0
        assert "out" in result.stdout
        assert not result.timed_out
        assert not result.truncated

    def test_exit_code_propagated(self, monkeypatch):
        monkeypatch.setenv("SSH_MCP_ALLOWED_CIDRS", "10.0.0.0/8")
        result = self._run(exit_code=42)
        assert result.exit_code == 42

    def test_stderr_returned_separately(self, monkeypatch):
        monkeypatch.setenv("SSH_MCP_ALLOWED_CIDRS", "10.0.0.0/8")
        result = self._run(stdout=b"out\n", stderr=b"err\n")
        assert "out" in result.stdout
        assert "err" in result.stderr

    def test_truncation(self, monkeypatch):
        monkeypatch.setenv("SSH_MCP_ALLOWED_CIDRS", "10.0.0.0/8")
        big_output = b"x" * 200
        result = self._run(stdout=big_output, max_output_bytes=50)
        assert result.truncated
        assert len(result.stdout) <= 50

    def test_duration_recorded(self, monkeypatch):
        monkeypatch.setenv("SSH_MCP_ALLOWED_CIDRS", "10.0.0.0/8")
        result = self._run()
        assert result.duration_seconds >= 0


# ---------------------------------------------------------------------------
# put_file / get_file tests
# ---------------------------------------------------------------------------


class TestFileTransfer:
    def _make_sftp_client(self):
        sftp = MagicMock()
        fh = MagicMock()
        fh.__enter__ = lambda s: s
        fh.__exit__ = MagicMock(return_value=False)
        sftp.open.return_value = fh
        return sftp, fh

    def test_put_file(self):
        mock_client = MagicMock()
        sftp, fh = self._make_sftp_client()
        mock_client.open_sftp.return_value = sftp
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport

        pool = MagicMock()
        pool.acquire.return_value = mock_client

        put_file(
            host="10.0.0.1",
            username="user",
            remote_path="/tmp/test.txt",
            content="hello world\n",
            pool=pool,
        )

        sftp.open.assert_called_once_with("/tmp/test.txt", "w")
        fh.write.assert_called_once_with("hello world\n")
        pool.release.assert_called_once()

    def test_get_file_no_truncation(self):
        mock_client = MagicMock()
        sftp, fh = self._make_sftp_client()
        stat_result = MagicMock()
        stat_result.st_size = 5
        sftp.stat.return_value = stat_result
        fh.read.return_value = b"hello"
        mock_client.open_sftp.return_value = sftp
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport

        pool = MagicMock()
        pool.acquire.return_value = mock_client

        content, truncated = get_file(
            host="10.0.0.1",
            username="user",
            remote_path="/tmp/test.txt",
            pool=pool,
        )

        assert content == "hello"
        assert not truncated

    def test_get_file_truncation(self):
        mock_client = MagicMock()
        sftp, fh = self._make_sftp_client()
        stat_result = MagicMock()
        stat_result.st_size = 1000
        sftp.stat.return_value = stat_result
        fh.read.return_value = b"x" * 10
        mock_client.open_sftp.return_value = sftp
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport

        pool = MagicMock()
        pool.acquire.return_value = mock_client

        content, truncated = get_file(
            host="10.0.0.1",
            username="user",
            remote_path="/tmp/big.txt",
            max_bytes=10,
            pool=pool,
        )

        assert truncated
        assert len(content) == 10
