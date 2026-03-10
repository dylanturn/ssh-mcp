"""FastMCP server exposing SSH tools for remote Linux command execution.

Transport selection
-------------------
The server supports two transports, chosen via the ``SSH_MCP_TRANSPORT``
environment variable (or the ``--transport`` CLI flag):

* ``stdio``  (default) — standard MCP over stdin / stdout.
* ``streamable-http`` — HTTP server (use ``SSH_MCP_HOST`` / ``SSH_MCP_PORT``
  to configure the bind address).

Usage
-----
::

    # STDIO (default)
    python -m ssh_mcp.server

    # HTTP
    SSH_MCP_TRANSPORT=streamable-http SSH_MCP_PORT=8080 python -m ssh_mcp.server

    # Via the installed entry-point
    ssh-mcp --transport streamable-http --port 8080

Configuration
-------------
All configuration is through environment variables documented in
:mod:`ssh_mcp.config`.  The most important one is
``SSH_MCP_ALLOWED_CIDRS`` — the server **denies all connections** when it is
not set.
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Annotated, Optional

from fastmcp import FastMCP
from pydantic import Field

from .config import get_settings
from .connection import execute_command, get_file, put_file
from .security import CIDRValidationError, validate_host

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stderr,
    )


# ---------------------------------------------------------------------------
# FastMCP instance
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "ssh-mcp",
    instructions=(
        "MCP server providing SSH access to remote Linux systems. "
        "Every tool requires specifying the target host and credentials. "
        "Connections are restricted to the configured CIDR allowlist."
    ),
)


# ---------------------------------------------------------------------------
# Shared annotation types
# ---------------------------------------------------------------------------

HostField = Annotated[str, Field(description="Hostname or IP address of the remote system.")]
UsernameField = Annotated[str, Field(description="SSH username to authenticate as.")]
PasswordField = Annotated[
    Optional[str],
    Field(default=None, description="SSH password. Omit when using key-based auth."),
]
KeyPathField = Annotated[
    Optional[str],
    Field(
        default=None,
        description=(
            "Absolute path to the SSH private key file on the *server*. "
            "Falls back to SSH_MCP_DEFAULT_KEY_PATH when omitted."
        ),
    ),
]
PortField = Annotated[int, Field(default=22, ge=1, le=65535, description="SSH port (default 22).")]


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def execute_ssh_command(
    host: HostField,
    username: UsernameField,
    command: Annotated[str, Field(description="Shell command to execute on the remote host.")],
    password: PasswordField = None,
    key_path: KeyPathField = None,
    port: PortField = 22,
    cwd: Annotated[
        Optional[str],
        Field(
            default=None,
            description=(
                "Working directory for this command. "
                "Does not persist across calls (stateless). "
                "Defaults to the user's home directory."
            ),
        ),
    ] = None,
    timeout: Annotated[
        Optional[int],
        Field(
            default=None,
            ge=1,
            description=(
                "Command timeout in seconds. "
                "Defaults to SSH_MCP_DEFAULT_TIMEOUT (30 s). "
                "Use a larger value for long operations such as package installs."
            ),
        ),
    ] = None,
    max_output_bytes: Annotated[
        Optional[int],
        Field(
            default=None,
            ge=1,
            description=(
                "Maximum combined stdout+stderr bytes to return. "
                "Output beyond this limit is silently dropped and "
                "``truncated`` will be set to ``true``. "
                "Defaults to SSH_MCP_MAX_OUTPUT_BYTES (1 MiB)."
            ),
        ),
    ] = None,
    sudo_password: Annotated[
        Optional[str],
        Field(
            default=None,
            description=(
                "If provided, the command is run via ``sudo -S`` and this "
                "value is piped to sudo's stdin. Leave unset for NOPASSWD sudo."
            ),
        ),
    ] = None,
) -> dict:
    """Execute a shell command on a remote Linux host via SSH.

    Returns a dictionary with:

    - **stdout** (str): Standard output of the command.
    - **stderr** (str): Standard error of the command.
    - **exit_code** (int): Process exit code, or ``-1`` on timeout.
    - **timed_out** (bool): ``true`` if the command exceeded the timeout.
    - **truncated** (bool): ``true`` if output was cut off at *max_output_bytes*.
    - **duration_seconds** (float): Wall-clock execution time.
    """
    try:
        validate_host(host)
    except CIDRValidationError as exc:
        return {"error": str(exc)}

    result = execute_command(
        host=host,
        username=username,
        command=command,
        password=password,
        key_path=key_path,
        port=port,
        cwd=cwd,
        timeout=timeout,
        max_output_bytes=max_output_bytes,
        sudo_password=sudo_password,
    )
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.exit_code,
        "timed_out": result.timed_out,
        "truncated": result.truncated,
        "duration_seconds": result.duration_seconds,
    }


@mcp.tool()
def upload_file(
    host: HostField,
    username: UsernameField,
    remote_path: Annotated[
        str,
        Field(description="Destination path on the remote host (absolute or relative to home)."),
    ],
    content: Annotated[
        str,
        Field(description="UTF-8 text content to write to the remote file."),
    ],
    password: PasswordField = None,
    key_path: KeyPathField = None,
    port: PortField = 22,
) -> dict:
    """Upload a text file to a remote host over SFTP.

    Returns a dictionary with:

    - **success** (bool): ``true`` on success.
    - **remote_path** (str): The destination path that was written.
    - **bytes_written** (int): Number of bytes written.
    """
    try:
        validate_host(host)
    except CIDRValidationError as exc:
        return {"error": str(exc)}

    put_file(
        host=host,
        username=username,
        remote_path=remote_path,
        content=content,
        password=password,
        key_path=key_path,
        port=port,
    )
    return {
        "success": True,
        "remote_path": remote_path,
        "bytes_written": len(content.encode("utf-8")),
    }


@mcp.tool()
def download_file(
    host: HostField,
    username: UsernameField,
    remote_path: Annotated[
        str,
        Field(description="Path on the remote host to download."),
    ],
    password: PasswordField = None,
    key_path: KeyPathField = None,
    port: PortField = 22,
    max_bytes: Annotated[
        Optional[int],
        Field(
            default=None,
            ge=1,
            description=(
                "Maximum bytes to return. "
                "Defaults to SSH_MCP_MAX_OUTPUT_BYTES (1 MiB). "
                "If the file is larger, only the first *max_bytes* bytes are returned "
                "and ``truncated`` will be ``true``."
            ),
        ),
    ] = None,
) -> dict:
    """Download a text file from a remote host over SFTP.

    Returns a dictionary with:

    - **content** (str): UTF-8 decoded file contents.
    - **remote_path** (str): The path that was read.
    - **truncated** (bool): ``true`` if the file exceeded *max_bytes*.
    """
    try:
        validate_host(host)
    except CIDRValidationError as exc:
        return {"error": str(exc)}

    content, truncated = get_file(
        host=host,
        username=username,
        remote_path=remote_path,
        password=password,
        key_path=key_path,
        port=port,
        max_bytes=max_bytes,
    )
    return {
        "content": content,
        "remote_path": remote_path,
        "truncated": truncated,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    cfg = get_settings()
    parser = argparse.ArgumentParser(
        prog="ssh-mcp",
        description="MCP server providing SSH access to remote Linux systems.",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default=cfg.transport,
        help="Transport protocol (default: %(default)s).",
    )
    parser.add_argument(
        "--host",
        default=cfg.host,
        help="Bind host for HTTP transport (default: %(default)s).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=cfg.port,
        help="Bind port for HTTP transport (default: %(default)s).",
    )
    parser.add_argument(
        "--log-level",
        default=cfg.log_level,
        help="Logging level (default: %(default)s).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    _configure_logging(args.log_level)

    if args.transport == "streamable-http":
        mcp.run(
            transport="streamable-http",
            host=args.host,
            port=args.port,
        )
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
