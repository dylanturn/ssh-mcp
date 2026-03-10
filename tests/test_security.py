"""Tests for ssh_mcp.security — CIDR allowlist validation."""

from __future__ import annotations

import ipaddress
import socket
import unittest
from unittest.mock import patch

import pytest

from ssh_mcp.config import reset_settings
from ssh_mcp.security import CIDRValidationError, _resolve_host, validate_host


@pytest.fixture(autouse=True)
def reset_cfg():
    """Ensure the settings singleton is fresh for every test."""
    reset_settings()
    yield
    reset_settings()


class TestResolveHost:
    def test_ipv4_literal(self):
        addr = _resolve_host("192.168.1.1")
        assert addr == ipaddress.ip_address("192.168.1.1")

    def test_ipv6_literal(self):
        addr = _resolve_host("::1")
        assert addr == ipaddress.ip_address("::1")

    def test_hostname_resolved(self):
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [(None, None, None, None, ("10.0.0.5", 0))]
            addr = _resolve_host("some-vm.local")
        assert addr == ipaddress.ip_address("10.0.0.5")

    def test_hostname_resolution_failure(self):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("nxdomain")):
            with pytest.raises(socket.gaierror):
                _resolve_host("nonexistent.invalid")


class TestValidateHost:
    def test_deny_by_default_empty_list(self):
        with pytest.raises(CIDRValidationError, match="No allowed CIDRs"):
            validate_host("192.168.1.1", allowed_cidrs=[])

    def test_allow_ip_in_cidr(self):
        result = validate_host("10.0.0.5", allowed_cidrs=["10.0.0.0/8"])
        assert result == "10.0.0.5"

    def test_deny_ip_outside_cidr(self):
        with pytest.raises(CIDRValidationError, match="not within any allowed CIDR"):
            validate_host("172.16.0.1", allowed_cidrs=["10.0.0.0/8"])

    def test_multiple_cidrs_first_matches(self):
        result = validate_host("192.168.5.10", allowed_cidrs=["10.0.0.0/8", "192.168.0.0/16"])
        assert result == "192.168.5.10"

    def test_multiple_cidrs_second_matches(self):
        result = validate_host("172.16.1.1", allowed_cidrs=["192.168.0.0/16", "172.16.0.0/12"])
        assert result == "172.16.1.1"

    def test_invalid_cidr_in_allowlist(self):
        with pytest.raises(CIDRValidationError, match="Invalid CIDR"):
            validate_host("10.0.0.1", allowed_cidrs=["not-a-cidr"])

    def test_hostname_dns_then_ip_check(self):
        """Hostname should be resolved first, then the resulting IP is checked."""
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [(None, None, None, None, ("10.1.2.3", 0))]
            result = validate_host("server.internal", allowed_cidrs=["10.0.0.0/8"])
        assert result == "server.internal"

    def test_hostname_resolved_ip_outside_cidr(self):
        """DNS resolves to an IP outside the allowed range → denied."""
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [(None, None, None, None, ("172.16.5.5", 0))]
            with pytest.raises(CIDRValidationError, match="not within any allowed CIDR"):
                validate_host("evil.example.com", allowed_cidrs=["10.0.0.0/8"])

    def test_ipv6_in_cidr(self):
        result = validate_host("::1", allowed_cidrs=["::1/128"])
        assert result == "::1"

    def test_exact_host_cidr(self):
        result = validate_host("10.0.0.1", allowed_cidrs=["10.0.0.1/32"])
        assert result == "10.0.0.1"

    def test_host_just_outside_cidr(self):
        with pytest.raises(CIDRValidationError):
            validate_host("10.0.0.2", allowed_cidrs=["10.0.0.1/32"])

    def test_uses_settings_when_no_cidrs_arg(self, monkeypatch):
        """validate_host reads from Settings when allowed_cidrs is not passed."""
        monkeypatch.setenv("SSH_MCP_ALLOWED_CIDRS", "192.168.0.0/16")
        reset_settings()
        result = validate_host("192.168.1.100")
        assert result == "192.168.1.100"

    def test_deny_by_default_via_settings(self):
        """When SSH_MCP_ALLOWED_CIDRS is not set, all connections must be denied."""
        # reset_settings() is called by the autouse fixture; env var not set
        with pytest.raises(CIDRValidationError, match="No allowed CIDRs"):
            validate_host("10.0.0.1")
