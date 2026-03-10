"""Configuration for ssh-mcp loaded from environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration sourced from environment variables.

    Environment variables (all optional, with sane defaults):

    - ``SSH_MCP_ALLOWED_CIDRS``: Comma-separated list of CIDR ranges the
      agent is allowed to SSH into, e.g. ``192.168.1.0/24,10.0.0.0/8``.
      **If empty or unset, all connections are denied (deny-by-default).**
    - ``SSH_MCP_DEFAULT_KEY_PATH``: Path to the default private SSH key
      used when no ``key_path`` is provided per-call.
    - ``SSH_MCP_DEFAULT_TIMEOUT``: Default command timeout in seconds (30).
    - ``SSH_MCP_MAX_OUTPUT_BYTES``: Default maximum output size in bytes
      before truncation (1 048 576 = 1 MiB).
    - ``SSH_MCP_POOL_MAX_IDLE``: Maximum idle connections per target (5).
    - ``SSH_MCP_LOG_LEVEL``: Python logging level name, e.g. ``INFO``.
    - ``SSH_MCP_TRANSPORT``: ``stdio`` (default) or ``streamable-http``.
    - ``SSH_MCP_HOST``: Bind host for HTTP transport (``0.0.0.0``).
    - ``SSH_MCP_PORT``: Bind port for HTTP transport (8000).
    - ``SSH_MCP_HOST_KEY_POLICY``: How to handle unknown SSH host keys.
      ``"reject"`` (default) — only connect to hosts whose keys are in the
      system known_hosts file (most secure).  ``"auto_add"`` — accept any
      host key and record it in memory (convenient for dynamic VMs, but
      susceptible to MITM on first connect).
    - ``SSH_MCP_KNOWN_HOSTS_PATH``: Path to a known_hosts file loaded in
      addition to the system default.  Only used when
      ``SSH_MCP_HOST_KEY_POLICY=reject``.
    """

    model_config = SettingsConfigDict(
        env_prefix="SSH_MCP_",
        populate_by_name=True,
    )

    # Security — stored as a raw comma-separated string so pydantic-settings
    # does not attempt JSON parsing.  Use the ``get_allowed_cidrs()`` method
    # to get the parsed list.
    allowed_cidrs: str = ""

    # SSH host key verification
    host_key_policy: str = "reject"
    known_hosts_path: str | None = None

    # SSH defaults
    default_key_path: str | None = None
    default_timeout: int = 30
    max_output_bytes: int = 1_048_576  # 1 MiB

    # Connection pool
    pool_max_idle: int = 5

    # Logging
    log_level: str = "INFO"

    # Transport
    transport: str = "stdio"
    host: str = "0.0.0.0"
    port: int = 8000

    def get_allowed_cidrs(self) -> list[str]:
        """Return the parsed list of allowed CIDR strings."""
        return [c.strip() for c in self.allowed_cidrs.split(",") if c.strip()]


_settings: Settings | None = None


def get_settings() -> Settings:
    """Return the process-wide Settings singleton."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    """Reset the singleton (used in tests to apply env-var overrides)."""
    global _settings
    _settings = None
