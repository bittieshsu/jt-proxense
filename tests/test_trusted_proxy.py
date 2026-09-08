"""X-Forwarded-For is an attacker-controlled header until proven otherwise.

Whatever survives here becomes the identity the per-IP login lockout counts
against, and the source_ip written into every audit row.
"""
from __future__ import annotations

import pytest

from server import middleware as mw


class _Req:
    def __init__(self, remote, xff=None):
        self.remote = remote
        self.headers = {"X-Forwarded-For": xff} if xff else {}


@pytest.fixture(autouse=True)
def _no_config(monkeypatch):
    """No trusted_proxies configured — the default an operator starts from."""
    class _Auth:
        trusted_proxies: list = []
    class _Cfg:
        auth = _Auth()
    monkeypatch.setattr(mw.config_mod, "get_config", lambda: _Cfg())
    mw._XFF_IGNORED_SEEN.clear()


@pytest.mark.parametrize("peer", [
    "192.168.1.50",     # same LAN — the realistic attacker against an internal tool
    "10.20.30.40",
    "172.16.5.5",
    "169.254.1.1",      # link-local
])
def test_lan_peer_cannot_forge_its_own_source_ip(peer):
    """These were all trusted implicitly, so anyone on the LAN could dodge the
    per-IP login lockout by sending a fresh XFF value on each attempt."""
    assert mw._is_trusted_proxy(peer) is False
    assert mw._client_ip(_Req(peer, xff="1.2.3.4")) == peer


def test_loopback_proxy_still_works():
    """The documented deployment: nginx terminating TLS in front of
    127.0.0.1:8098 on the same host."""
    assert mw._is_trusted_proxy("127.0.0.1") is True
    assert mw._client_ip(_Req("127.0.0.1", xff="203.0.113.9")) == "203.0.113.9"


def test_named_proxy_is_honoured(monkeypatch):
    class _Auth:
        trusted_proxies = ["192.168.1.5"]
    class _Cfg:
        auth = _Auth()
    monkeypatch.setattr(mw.config_mod, "get_config", lambda: _Cfg())
    assert mw._client_ip(_Req("192.168.1.5", xff="203.0.113.9")) == "203.0.113.9"
    assert mw._client_ip(_Req("192.168.1.6", xff="203.0.113.9")) == "192.168.1.6"


def test_cidr_entries_still_work(monkeypatch):
    class _Auth:
        trusted_proxies = ["192.168.1.0/24"]
    class _Cfg:
        auth = _Auth()
    monkeypatch.setattr(mw.config_mod, "get_config", lambda: _Cfg())
    assert mw._client_ip(_Req("192.168.1.77", xff="203.0.113.9")) == "203.0.113.9"


def test_first_hop_is_taken_not_the_last():
    """XFF is a client-appended chain; the leftmost entry is the original
    client as recorded by the first trusted hop."""
    assert mw._client_ip(
        _Req("127.0.0.1", xff="203.0.113.9, 10.0.0.1, 10.0.0.2")) == "203.0.113.9"


def test_ignored_xff_is_logged_once_per_peer(caplog):
    """An operator whose proxy moved off-host needs to be told, or every audit
    row silently changes meaning."""
    import logging
    with caplog.at_level(logging.WARNING, logger=mw.logger.name):
        mw._client_ip(_Req("192.168.1.50", xff="1.2.3.4"))
        mw._client_ip(_Req("192.168.1.50", xff="1.2.3.4"))
    hits = [r for r in caplog.records if "X-Forwarded-For" in r.getMessage()]
    assert len(hits) == 1, f"expected one warning per peer, got {len(hits)}"
