# ssh-mcp
An MCP server that allows AI Agents to SSH with guardrails

## Overview

`ssh-mcp` is a [FastMCP](https://github.com/jlowin/fastmcp)-based MCP server that lets AI agents securely SSH into remote Linux systems. It exposes three MCP tools:

| Tool | Description |
|------|-------------|
| `execute_ssh_command` | Run a shell command on a remote host and receive **stdout**, **stderr**, and **exit code** as separate fields |
| `upload_file` | Push a text file to a remote host over SFTP |
| `download_file` | Pull a text file from a remote host over SFTP |

### Key features

* **Per-call connection targeting** — specify host, username, and credentials on every call; no single pre-configured target required
* **Connection pooling** — SSH handshakes are reused across calls to the same `(host, port, username)` triple
* **Graceful timeout** — commands are bounded by a configurable timeout; on expiry the remote process receives `SIGTERM`, then `SIGKILL` after a grace period, and partial output is still returned
* **CIDR allowlist** — all targets are validated against a list of allowed CIDR ranges *after* DNS resolution; deny-by-default when no CIDRs are configured
* **Output size limits** — responses are truncated at a configurable byte limit to protect the AI context window
* **Optional `cwd`** — stateless execution with an optional per-call working directory
* **Sudo support** — pass a `sudo_password` per-call for password-based sudo; NOPASSWD sudo works without it
* **Structured command logging** — timestamp, host, command, exit code, and duration are logged on every execution
* **Dual transport** — run as a STDIO server (default) or as a streaming-HTTP server

---

## Installation

```bash
pip install ssh-mcp
```

Or from source:

```bash
git clone https://github.com/dylanturn/ssh-mcp
cd ssh-mcp
pip install -e .
```

---

## Configuration

All configuration is through **environment variables**:

| Variable | Default | Description |
|----------|---------|-------------|
| `SSH_MCP_ALLOWED_CIDRS` | *(empty)* | **Required.** Comma-separated CIDR ranges the agent may SSH into, e.g. `10.0.0.0/8,192.168.0.0/16`. If empty, **all connections are denied**. |
| `SSH_MCP_HOST_KEY_POLICY` | `reject` | `reject` (default, uses system known_hosts — most secure) or `auto_add` (accept any key, suitable for dynamic VMs on trusted networks). |
| `SSH_MCP_KNOWN_HOSTS_PATH` | *(none)* | Path to an additional known_hosts file (used when `SSH_MCP_HOST_KEY_POLICY=reject`). |
| `SSH_MCP_DEFAULT_KEY_PATH` | *(none)* | Path on the server to the default SSH private key file. Overridden per-call via `key_path`. |
| `SSH_MCP_DEFAULT_TIMEOUT` | `30` | Default command timeout in seconds. |
| `SSH_MCP_MAX_OUTPUT_BYTES` | `1048576` | Maximum response bytes (stdout+stderr) before truncation (1 MiB). |
| `SSH_MCP_POOL_MAX_IDLE` | `5` | Maximum idle connections per `(host, port, username)` triple. |
| `SSH_MCP_LOG_LEVEL` | `INFO` | Python logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |
| `SSH_MCP_TRANSPORT` | `stdio` | `stdio` or `streamable-http`. |
| `SSH_MCP_HOST` | `0.0.0.0` | Bind host for HTTP transport. |
| `SSH_MCP_PORT` | `8000` | Bind port for HTTP transport. |

### Security: CIDR allowlist

`SSH_MCP_ALLOWED_CIDRS` is the primary security control. The server **resolves hostnames to IP addresses before checking them** against the allowlist, preventing DNS-based bypasses.

```bash
export SSH_MCP_ALLOWED_CIDRS="10.10.0.0/16,192.168.100.0/24"
```

If the variable is unset or empty, every SSH attempt returns an error immediately.

---

## Usage

### STDIO transport (default — for use with MCP clients like Claude Desktop)

```bash
SSH_MCP_ALLOWED_CIDRS="10.0.0.0/8" ssh-mcp
# or
SSH_MCP_ALLOWED_CIDRS="10.0.0.0/8" python -m ssh_mcp
```

### HTTP transport

```bash
SSH_MCP_ALLOWED_CIDRS="10.0.0.0/8" \
SSH_MCP_TRANSPORT=streamable-http \
SSH_MCP_PORT=8080 \
  ssh-mcp
```

Or via CLI flags:

```bash
SSH_MCP_ALLOWED_CIDRS="10.0.0.0/8" ssh-mcp --transport streamable-http --port 8080
```

### Docker

A `Dockerfile` and `docker-compose.yml` are included. The container defaults to the `streamable-http` transport on port `8000`.

**Quick start with docker compose:**

```bash
SSH_MCP_ALLOWED_CIDRS="10.0.0.0/8,192.168.0.0/16" docker compose up
```

The server is then reachable at `http://localhost:8000/mcp`.

**Optional — use your host SSH keys inside the container:**

The compose file bind-mounts `~/.ssh` (read-only) into `/root/.ssh` so existing keys and `known_hosts` entries are available without any extra configuration. Set `SSH_DIR` to use a different directory:

```bash
SSH_DIR=/path/to/keys SSH_MCP_ALLOWED_CIDRS="10.0.0.0/8" docker compose up
```

Remove or comment out the `volumes` block in `docker-compose.yml` if you prefer to supply credentials per-call only.

**Build and run manually with `docker`:**

```bash
docker build -t ssh-mcp .

docker run --rm \
  -e SSH_MCP_ALLOWED_CIDRS="10.0.0.0/8" \
  -p 8000:8000 \
  ssh-mcp
```

---

## MCP Tool Reference

### `execute_ssh_command`

Execute a shell command on a remote Linux host.

**Parameters**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `host` | string | ✓ | Hostname or IP of the remote system |
| `username` | string | ✓ | SSH username |
| `command` | string | ✓ | Shell command to run |
| `password` | string | — | SSH password (omit for key auth) |
| `key_path` | string | — | Server-side path to SSH private key |
| `port` | integer | — | SSH port (default `22`) |
| `cwd` | string | — | Working directory for this command (stateless) |
| `timeout` | integer | — | Timeout in seconds (default: `SSH_MCP_DEFAULT_TIMEOUT`) |
| `max_output_bytes` | integer | — | Max output bytes before truncation |
| `sudo_password` | string | — | Password for `sudo -S`; omit for NOPASSWD |

**Response fields**

| Field | Type | Description |
|-------|------|-------------|
| `stdout` | string | Standard output |
| `stderr` | string | Standard error |
| `exit_code` | integer | Process exit code, or `-1` on timeout |
| `timed_out` | boolean | `true` if the command exceeded the timeout |
| `truncated` | boolean | `true` if output was cut at `max_output_bytes` |
| `duration_seconds` | float | Wall-clock execution time |

---

### `upload_file`

Upload a text file to a remote host via SFTP.

**Parameters**: `host`, `username`, `remote_path`, `content`, `password`, `key_path`, `port`

**Response**: `{ "success": true, "remote_path": "...", "bytes_written": N }`

---

### `download_file`

Download a text file from a remote host via SFTP.

**Parameters**: `host`, `username`, `remote_path`, `password`, `key_path`, `port`, `max_bytes`

**Response**: `{ "content": "...", "remote_path": "...", "truncated": false }`

---

## Development

```bash
pip install -e ".[dev]"
pytest
```

### Project layout

```
src/ssh_mcp/
├── __init__.py
├── __main__.py      # python -m ssh_mcp entry point
├── config.py        # pydantic-settings configuration
├── connection.py    # SSH connection pool + command execution
├── security.py      # CIDR allowlist validation
└── server.py        # FastMCP tool definitions + CLI entry point
tests/
├── test_security.py
├── test_connection.py
└── test_server.py
```
