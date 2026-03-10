"""SSH connection pool and command execution with graceful timeout handling.

Connection pooling
------------------
Connections are keyed by ``(host, port, username)``.  The pool keeps at most
``SSH_MCP_POOL_MAX_IDLE`` idle connections per key.  Before reusing a cached
connection, the transport is checked for liveness; stale connections are
discarded and a fresh one is opened.

Timeout / signal handling
--------------------------
Command execution follows the sequence required by the problem spec:

1. Execute the remote command via a dedicated paramiko channel.
2. Poll for output while wall-clock time remains.
3. **Timeout fires** → send ``SIGTERM`` to the remote process, then wait
   ``SIGTERM_GRACE_SECONDS`` for it to exit.
4. **Still alive** → send ``SIGKILL`` (collected via ``/proc`` look-up or
   channel close).
5. Collect all partial output already in the buffers.
6. Return the partial output together with ``timed_out=True``.

The remote process is identified by running the actual command through a small
wrapper shell snippet that emits the PID on a dedicated fd.
"""

from __future__ import annotations

import io
import logging
import os
import select
import socket
import stat
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

import paramiko

from .config import get_settings

logger = logging.getLogger(__name__)

# How long (seconds) to wait between SIGTERM and SIGKILL
SIGTERM_GRACE_SECONDS = 2
# How long (seconds) to wait for the channel to become ready after SIGKILL
POST_KILL_DRAIN_SECONDS = 1
# Polling interval while reading remote output
POLL_INTERVAL = 0.05


@dataclass
class CommandResult:
    """Result of a remote command execution."""

    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool = False
    truncated: bool = False
    duration_seconds: float = 0.0


@dataclass
class _PoolEntry:
    client: paramiko.SSHClient
    lock: threading.Lock = field(default_factory=threading.Lock)


class ConnectionPool:
    """Thread-safe SSH connection pool."""

    def __init__(self, max_idle: int | None = None) -> None:
        cfg = get_settings()
        self._max_idle = max_idle if max_idle is not None else cfg.pool_max_idle
        self._pool: dict[tuple, list[paramiko.SSHClient]] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_key(
        self,
        host: str,
        port: int,
        username: str,
    ) -> tuple[str, int, str]:
        return (host, port, username)

    def _is_alive(self, client: paramiko.SSHClient) -> bool:
        transport = client.get_transport()
        return transport is not None and transport.is_active()

    def _open_connection(
        self,
        host: str,
        port: int,
        username: str,
        password: str | None,
        key_path: str | None,
    ) -> paramiko.SSHClient:
        """Open and return a new authenticated SSH connection."""
        cfg = get_settings()
        effective_key = key_path or cfg.default_key_path

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict = {
            "hostname": host,
            "port": port,
            "username": username,
            "timeout": 10,
            "banner_timeout": 10,
            "auth_timeout": 10,
            "look_for_keys": False,
            "allow_agent": False,
        }

        if password:
            connect_kwargs["password"] = password
        if effective_key:
            connect_kwargs["key_filename"] = effective_key
            connect_kwargs["look_for_keys"] = False

        client.connect(**connect_kwargs)
        logger.debug("Opened new SSH connection to %s@%s:%s", username, host, port)
        return client

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def acquire(
        self,
        host: str,
        port: int,
        username: str,
        password: str | None,
        key_path: str | None,
    ) -> paramiko.SSHClient:
        """Return a live SSH client, reusing a pooled one if available."""
        key = self._make_key(host, port, username)
        with self._lock:
            candidates = self._pool.get(key, [])
            while candidates:
                client = candidates.pop()
                if self._is_alive(client):
                    logger.debug(
                        "Reusing pooled connection to %s@%s:%s", username, host, port
                    )
                    return client
                # stale — discard
                try:
                    client.close()
                except Exception:
                    pass

        # Nothing reusable — open fresh
        return self._open_connection(host, port, username, password, key_path)

    def release(self, host: str, port: int, username: str, client: paramiko.SSHClient) -> None:
        """Return a client to the pool if it is still alive and pool is not full."""
        if not self._is_alive(client):
            try:
                client.close()
            except Exception:
                pass
            return

        key = self._make_key(host, port, username)
        with self._lock:
            bucket = self._pool.setdefault(key, [])
            if len(bucket) < self._max_idle:
                bucket.append(client)
            else:
                client.close()

    def close_all(self) -> None:
        """Close every connection in the pool (used on shutdown)."""
        with self._lock:
            for bucket in self._pool.values():
                for client in bucket:
                    try:
                        client.close()
                    except Exception:
                        pass
            self._pool.clear()


# Process-wide default pool
_default_pool: ConnectionPool | None = None
_pool_lock = threading.Lock()


def get_pool() -> ConnectionPool:
    global _default_pool
    if _default_pool is None:
        with _pool_lock:
            if _default_pool is None:
                _default_pool = ConnectionPool()
    return _default_pool


def reset_pool() -> None:
    """Replace the default pool (used in tests)."""
    global _default_pool
    with _pool_lock:
        if _default_pool is not None:
            _default_pool.close_all()
        _default_pool = None


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------

def _drain(channel: paramiko.Channel, timeout: float) -> tuple[bytes, bytes]:
    """Read remaining stdout/stderr from *channel* up to *timeout* seconds."""
    stdout_buf = io.BytesIO()
    stderr_buf = io.BytesIO()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r, _, _ = select.select([channel], [], [], POLL_INTERVAL)
        if channel in r:
            if channel.recv_ready():
                chunk = channel.recv(4096)
                if chunk:
                    stdout_buf.write(chunk)
            if channel.recv_stderr_ready():
                chunk = channel.recv_stderr(4096)
                if chunk:
                    stderr_buf.write(chunk)
        if channel.closed or channel.exit_status_ready():
            # Final drain
            while channel.recv_ready():
                stdout_buf.write(channel.recv(4096))
            while channel.recv_stderr_ready():
                stderr_buf.write(channel.recv_stderr(4096))
            break
    return stdout_buf.getvalue(), stderr_buf.getvalue()


def execute_command(
    host: str,
    username: str,
    command: str,
    *,
    password: str | None = None,
    key_path: str | None = None,
    port: int = 22,
    cwd: str | None = None,
    timeout: int | None = None,
    max_output_bytes: int | None = None,
    sudo_password: str | None = None,
    pool: ConnectionPool | None = None,
) -> CommandResult:
    """Execute *command* on the remote host and return structured output.

    Parameters
    ----------
    host:
        Remote hostname or IP address (already CIDR-validated by the caller).
    username:
        SSH username.
    command:
        Shell command to execute.
    password:
        SSH password (optional; used for auth, not sudo).
    key_path:
        Path to an SSH private key file.
    port:
        SSH port (default 22).
    cwd:
        Working directory for the command (stateless; does not persist).
    timeout:
        Wall-clock timeout in seconds.  Defaults to
        ``SSH_MCP_DEFAULT_TIMEOUT``.
    max_output_bytes:
        Truncate combined output to this many bytes.  Defaults to
        ``SSH_MCP_MAX_OUTPUT_BYTES``.
    sudo_password:
        If provided, the command is prefixed with ``sudo -S`` and this
        password is piped to stdin.
    pool:
        Connection pool to use.  Defaults to the process-wide pool.
    """
    cfg = get_settings()
    effective_timeout = timeout if timeout is not None else cfg.default_timeout
    effective_max_bytes = max_output_bytes if max_output_bytes is not None else cfg.max_output_bytes

    if pool is None:
        pool = get_pool()

    # Build the actual shell invocation
    if cwd:
        escaped_cwd = cwd.replace("'", "'\\''")
        wrapped = f"cd '{escaped_cwd}' && {command}"
    else:
        wrapped = command

    if sudo_password:
        # Pipe password to sudo -S; -p '' suppresses the prompt
        escaped_pw = sudo_password.replace("'", "'\\''")
        full_command = f"echo '{escaped_pw}' | sudo -S -p '' sh -c {_shell_quote(wrapped)}"
    else:
        full_command = wrapped

    # We use a wrapper to capture the PID so we can SIGTERM/SIGKILL on timeout.
    # The PID is written to fd 3 (a pipe the server controls).
    # Actual remote command: bash -c 'echo $$; exec <cmd>'
    # We capture the first line of stdout (the PID) before returning the rest.
    pid_wrapper = f"bash -c 'echo $$>&3; exec {_shell_quote(full_command)}' 3>/tmp/.ssh_mcp_pid_$$"

    start_time = time.monotonic()
    client = pool.acquire(host, port, username, password, key_path)
    timed_out = False
    remote_pid: int | None = None

    try:
        transport = client.get_transport()
        channel = transport.open_session()
        channel.set_combine_stderr(False)
        # We need to capture the PID via a side channel. Use a simpler approach:
        # wrap command so it prints PID to stderr line first (with a sentinel).
        pid_sentinel = "__SSH_MCP_PID__:"
        actual_cmd = (
            f"bash -c 'printf \"{pid_sentinel}%s\\n\" $$ >&2; exec {_shell_quote(full_command)}'"
        )
        channel.exec_command(actual_cmd)

        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        total_bytes = 0
        truncated = False
        pid_line_buf = b""
        pid_extracted = False

        deadline = time.monotonic() + effective_timeout

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break

            wait = min(POLL_INTERVAL, remaining)
            r, _, _ = select.select([channel], [], [], wait)

            if channel in r or channel.recv_ready() or channel.recv_stderr_ready():
                # Read stdout
                if channel.recv_ready():
                    chunk = channel.recv(4096)
                    if chunk:
                        if total_bytes < effective_max_bytes:
                            take = min(len(chunk), effective_max_bytes - total_bytes)
                            stdout_chunks.append(chunk[:take])
                            total_bytes += take
                            if take < len(chunk):
                                truncated = True

                # Read stderr (also where our PID sentinel lives)
                if channel.recv_stderr_ready():
                    chunk = channel.recv_stderr(4096)
                    if chunk:
                        if not pid_extracted:
                            pid_line_buf += chunk
                            if b"\n" in pid_line_buf:
                                first_nl = pid_line_buf.index(b"\n")
                                first_line = pid_line_buf[:first_nl].decode("utf-8", errors="replace")
                                rest = pid_line_buf[first_nl + 1 :]
                                if pid_sentinel in first_line:
                                    try:
                                        remote_pid = int(first_line.split(pid_sentinel, 1)[1].strip())
                                    except ValueError:
                                        pass
                                    pid_extracted = True
                                    chunk = rest
                                    pid_line_buf = b""
                                else:
                                    # Not our sentinel line, keep buffering
                                    pid_extracted = True  # stop trying
                                    chunk = pid_line_buf
                                    pid_line_buf = b""
                            else:
                                continue  # keep buffering

                        if total_bytes < effective_max_bytes:
                            take = min(len(chunk), effective_max_bytes - total_bytes)
                            stderr_chunks.append(chunk[:take])
                            total_bytes += take
                            if take < len(chunk):
                                truncated = True

            if channel.exit_status_ready():
                # Final drain
                while channel.recv_ready():
                    chunk = channel.recv(4096)
                    if chunk and total_bytes < effective_max_bytes:
                        take = min(len(chunk), effective_max_bytes - total_bytes)
                        stdout_chunks.append(chunk[:take])
                        total_bytes += take
                        if take < len(chunk):
                            truncated = True
                while channel.recv_stderr_ready():
                    chunk = channel.recv_stderr(4096)
                    if chunk and total_bytes < effective_max_bytes:
                        take = min(len(chunk), effective_max_bytes - total_bytes)
                        stderr_chunks.append(chunk[:take])
                        total_bytes += take
                        if take < len(chunk):
                            truncated = True
                break

        if timed_out:
            _kill_remote(client, remote_pid, channel)
            # Brief drain of partial output
            partial_stdout, partial_stderr = _drain(channel, POST_KILL_DRAIN_SECONDS)
            if partial_stdout and total_bytes < effective_max_bytes:
                take = min(len(partial_stdout), effective_max_bytes - total_bytes)
                stdout_chunks.append(partial_stdout[:take])
            if partial_stderr and total_bytes < effective_max_bytes:
                take = min(len(partial_stderr), effective_max_bytes - total_bytes)
                stderr_chunks.append(partial_stderr[:take])

        exit_code = channel.recv_exit_status() if not timed_out else -1
        channel.close()

    finally:
        duration = time.monotonic() - start_time
        pool.release(host, port, username, client)

    stdout_str = b"".join(stdout_chunks).decode("utf-8", errors="replace")
    stderr_str = b"".join(stderr_chunks).decode("utf-8", errors="replace")

    logger.info(
        "CMD host=%s user=%s exit=%s timeout=%s duration=%.2fs cmd=%r",
        host,
        username,
        exit_code if not timed_out else "TIMEOUT",
        timed_out,
        duration,
        command[:200],
    )

    return CommandResult(
        stdout=stdout_str,
        stderr=stderr_str,
        exit_code=exit_code,
        timed_out=timed_out,
        truncated=truncated,
        duration_seconds=round(duration, 3),
    )


def _kill_remote(
    client: paramiko.SSHClient,
    remote_pid: int | None,
    channel: paramiko.Channel,
) -> None:
    """Send SIGTERM → wait → SIGKILL to the remote process."""
    if remote_pid is not None:
        try:
            # Send SIGTERM via a new channel so the original keeps draining
            transport = client.get_transport()
            if transport and transport.is_active():
                kill_cmd = (
                    f"kill -TERM {remote_pid} 2>/dev/null; "
                    f"sleep {SIGTERM_GRACE_SECONDS}; "
                    f"kill -KILL {remote_pid} 2>/dev/null"
                )
                kill_ch = transport.open_session()
                kill_ch.exec_command(kill_cmd)
                kill_ch.recv_exit_status()
                kill_ch.close()
        except Exception as exc:
            logger.debug("Failed to signal remote PID %s: %s", remote_pid, exc)
    else:
        # No PID captured — just close the channel; the remote may become orphaned
        logger.debug("No remote PID available; closing channel without signaling")
    try:
        channel.close()
    except Exception:
        pass


def _shell_quote(s: str) -> str:
    """Minimally safe single-quote wrapping for shell arguments."""
    return "'" + s.replace("'", "'\\''") + "'"


# ---------------------------------------------------------------------------
# File transfer
# ---------------------------------------------------------------------------

def put_file(
    host: str,
    username: str,
    remote_path: str,
    content: str,
    *,
    password: str | None = None,
    key_path: str | None = None,
    port: int = 22,
    pool: ConnectionPool | None = None,
) -> None:
    """Write *content* (UTF-8 text) to *remote_path* on the target host.

    Parameters
    ----------
    host, username, password, key_path, port:
        Connection parameters.
    remote_path:
        Absolute or relative path on the remote host where the file is written.
    content:
        Text content to write.
    pool:
        Connection pool to use.
    """
    if pool is None:
        pool = get_pool()

    client = pool.acquire(host, port, username, password, key_path)
    try:
        sftp = client.open_sftp()
        try:
            with sftp.open(remote_path, "w") as remote_fh:
                remote_fh.write(content)
        finally:
            sftp.close()
        logger.info("PUT host=%s user=%s remote_path=%r bytes=%d", host, username, remote_path, len(content))
    finally:
        pool.release(host, port, username, client)


def get_file(
    host: str,
    username: str,
    remote_path: str,
    *,
    password: str | None = None,
    key_path: str | None = None,
    port: int = 22,
    max_bytes: int | None = None,
    pool: ConnectionPool | None = None,
) -> tuple[str, bool]:
    """Read and return the contents of *remote_path* as UTF-8 text.

    Parameters
    ----------
    host, username, password, key_path, port:
        Connection parameters.
    remote_path:
        Path on the remote host to read.
    max_bytes:
        Maximum bytes to read.  Defaults to ``SSH_MCP_MAX_OUTPUT_BYTES``.
    pool:
        Connection pool to use.

    Returns
    -------
    tuple[str, bool]
        ``(content, truncated)`` where *truncated* is ``True`` if the file
        was larger than *max_bytes* and only a prefix was returned.
    """
    cfg = get_settings()
    effective_max = max_bytes if max_bytes is not None else cfg.max_output_bytes

    if pool is None:
        pool = get_pool()

    client = pool.acquire(host, port, username, password, key_path)
    try:
        sftp = client.open_sftp()
        try:
            file_stat = sftp.stat(remote_path)
            file_size = file_stat.st_size or 0
            truncated = file_size > effective_max
            with sftp.open(remote_path, "r") as remote_fh:
                raw = remote_fh.read(effective_max)
        finally:
            sftp.close()
        logger.info(
            "GET host=%s user=%s remote_path=%r bytes_read=%d truncated=%s",
            host, username, remote_path, len(raw), truncated,
        )
        return raw.decode("utf-8", errors="replace"), truncated
    finally:
        pool.release(host, port, username, client)
