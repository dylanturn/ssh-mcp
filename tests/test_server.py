"""Tests for ssh_mcp.server — FastMCP tool definitions."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from ssh_mcp.config import reset_settings
from ssh_mcp.connection import CommandResult, reset_pool
from ssh_mcp.security import CIDRValidationError
from ssh_mcp.server import download_file, execute_ssh_command, upload_file


@pytest.fixture(autouse=True)
def reset_state():
    reset_settings()
    reset_pool()
    yield
    reset_settings()
    reset_pool()


class TestExecuteSshCommand:
    def test_cidr_denial_short_circuits(self):
        with patch("ssh_mcp.server.validate_host", side_effect=CIDRValidationError("denied")):
            result = execute_ssh_command(host="10.0.0.1", username="user", command="ls")
        assert "error" in result
        assert "denied" in result["error"]

    def test_success_returns_structured_output(self, monkeypatch):
        monkeypatch.setenv("SSH_MCP_ALLOWED_CIDRS", "10.0.0.0/8")
        reset_settings()

        mock_result = CommandResult(
            stdout="hello\n",
            stderr="",
            exit_code=0,
            timed_out=False,
            truncated=False,
            duration_seconds=0.1,
        )
        with patch("ssh_mcp.server.validate_host", return_value="10.0.0.1"), \
             patch("ssh_mcp.server.execute_command", return_value=mock_result):
            result = execute_ssh_command(host="10.0.0.1", username="user", command="echo hello")

        assert result["stdout"] == "hello\n"
        assert result["stderr"] == ""
        assert result["exit_code"] == 0
        assert result["timed_out"] is False
        assert result["truncated"] is False
        assert result["duration_seconds"] == 0.1

    def test_timeout_flag_propagated(self, monkeypatch):
        monkeypatch.setenv("SSH_MCP_ALLOWED_CIDRS", "10.0.0.0/8")
        reset_settings()

        mock_result = CommandResult(
            stdout="partial",
            stderr="",
            exit_code=-1,
            timed_out=True,
            truncated=False,
            duration_seconds=30.0,
        )
        with patch("ssh_mcp.server.validate_host", return_value="10.0.0.1"), \
             patch("ssh_mcp.server.execute_command", return_value=mock_result):
            result = execute_ssh_command(host="10.0.0.1", username="user", command="sleep 100")

        assert result["timed_out"] is True
        assert result["exit_code"] == -1
        assert result["stdout"] == "partial"

    def test_truncated_flag_propagated(self, monkeypatch):
        monkeypatch.setenv("SSH_MCP_ALLOWED_CIDRS", "10.0.0.0/8")
        reset_settings()

        mock_result = CommandResult(
            stdout="x" * 100,
            stderr="",
            exit_code=0,
            timed_out=False,
            truncated=True,
            duration_seconds=1.0,
        )
        with patch("ssh_mcp.server.validate_host", return_value="10.0.0.1"), \
             patch("ssh_mcp.server.execute_command", return_value=mock_result):
            result = execute_ssh_command(
                host="10.0.0.1", username="user", command="cat bigfile", max_output_bytes=100
            )

        assert result["truncated"] is True


class TestUploadFile:
    def test_cidr_denial(self):
        with patch("ssh_mcp.server.validate_host", side_effect=CIDRValidationError("denied")):
            result = upload_file(
                host="10.0.0.1",
                username="user",
                remote_path="/tmp/f",
                content="data",
            )
        assert "error" in result

    def test_success(self):
        with patch("ssh_mcp.server.validate_host", return_value="10.0.0.1"), \
             patch("ssh_mcp.server.put_file") as mock_put:
            result = upload_file(
                host="10.0.0.1",
                username="user",
                remote_path="/tmp/test.txt",
                content="hello",
            )
        mock_put.assert_called_once()
        assert result["success"] is True
        assert result["remote_path"] == "/tmp/test.txt"
        assert result["bytes_written"] == 5  # len("hello")


class TestDownloadFile:
    def test_cidr_denial(self):
        with patch("ssh_mcp.server.validate_host", side_effect=CIDRValidationError("denied")):
            result = download_file(
                host="10.0.0.1",
                username="user",
                remote_path="/tmp/f",
            )
        assert "error" in result

    def test_success_not_truncated(self):
        with patch("ssh_mcp.server.validate_host", return_value="10.0.0.1"), \
             patch("ssh_mcp.server.get_file", return_value=("file content", False)):
            result = download_file(
                host="10.0.0.1",
                username="user",
                remote_path="/tmp/test.txt",
            )
        assert result["content"] == "file content"
        assert result["truncated"] is False
        assert result["remote_path"] == "/tmp/test.txt"

    def test_success_truncated(self):
        with patch("ssh_mcp.server.validate_host", return_value="10.0.0.1"), \
             patch("ssh_mcp.server.get_file", return_value=("partial", True)):
            result = download_file(
                host="10.0.0.1",
                username="user",
                remote_path="/var/log/big.log",
                max_bytes=100,
            )
        assert result["truncated"] is True
        assert result["content"] == "partial"
