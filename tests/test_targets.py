import socket

import pytest

from cg_threat_intel.services.targets import TargetValidationError, validate_public_https_target


def test_rejects_non_https_and_credentials() -> None:
    with pytest.raises(TargetValidationError):
        validate_public_https_target("http://example.com")
    with pytest.raises(TargetValidationError):
        validate_public_https_target("https://user:pass@example.com")


def test_rejects_private_resolved_addresses(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(None, None, None, None, ("127.0.0.1", 443))])

    with pytest.raises(TargetValidationError, match="private or reserved"):
        validate_public_https_target("https://example.com")


def test_allows_public_https_target(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(None, None, None, None, ("8.8.8.8", 443))])

    assert validate_public_https_target("https://example.com/health") == "https://example.com/health"
