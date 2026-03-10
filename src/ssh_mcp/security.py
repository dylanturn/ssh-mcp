"""CIDR-based host allowlist with DNS-first resolution.

Design goals
------------
* **Deny by default** — if ``allowed_cidrs`` is empty, every host is rejected.
* **DNS-then-IP validation** — hostnames are resolved to an IP address *before*
  the IP is checked against the allowlist, so crafted DNS names cannot be used
  to reach hosts outside the allowed ranges.
* Supports IPv4 and IPv6 CIDRs in standard notation.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Sequence

from .config import get_settings


class CIDRValidationError(ValueError):
    """Raised when a target host is not within any allowed CIDR."""


def _resolve_host(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Resolve *host* to an IP address object.

    For bare IP literals this is a no-op parse; for hostnames a DNS lookup
    is performed so the *actual* destination IP is validated.
    """
    try:
        # Fast path: already an IP literal
        return ipaddress.ip_address(host)
    except ValueError:
        pass

    # DNS resolution — raises socket.gaierror on failure
    info = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    if not info:
        raise CIDRValidationError(f"Could not resolve hostname: {host!r}")
    raw_ip = info[0][4][0]
    return ipaddress.ip_address(raw_ip)


def validate_host(host: str, allowed_cidrs: Sequence[str] | None = None) -> str:
    """Validate *host* against the configured (or supplied) CIDR allowlist.

    Parameters
    ----------
    host:
        Hostname or IP address of the SSH target.
    allowed_cidrs:
        Override the CIDRs from :func:`~ssh_mcp.config.get_settings`.
        Intended for testing only.

    Returns
    -------
    str
        The *host* argument, unchanged, if validation passes.

    Raises
    ------
    CIDRValidationError
        If the host is not in any allowed CIDR or the list is empty.
    socket.gaierror
        If the hostname cannot be resolved.
    """
    if allowed_cidrs is None:
        allowed_cidrs = get_settings().get_allowed_cidrs()

    if not allowed_cidrs:
        raise CIDRValidationError(
            "No allowed CIDRs configured — all SSH connections are denied. "
            "Set SSH_MCP_ALLOWED_CIDRS to a comma-separated list of CIDR ranges."
        )

    target_ip = _resolve_host(host)

    for cidr in allowed_cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise CIDRValidationError(f"Invalid CIDR in allowlist: {cidr!r}") from exc
        if target_ip in network:
            return host

    raise CIDRValidationError(
        f"Host {host!r} (resolved to {target_ip}) is not within any allowed CIDR: "
        f"{', '.join(allowed_cidrs)}"
    )
