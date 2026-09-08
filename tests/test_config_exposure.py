"""What GET /api/config hands out, and to whom.

In v1.0.1 this route carried NO role check (only the POST was admin-gated) and
masked exactly two fields, so any authenticated session -- including one with no
role grant at all -- could read server.influx_token and the auth.ldap bind
password along with the whole cluster inventory.
"""
from __future__ import annotations

import pytest

from server import config as cfg_mod
from server import server as srv


def _full_config_dict():
    c = cfg_mod.Config.from_dict({
        "server": {"host": "10.0.0.9", "influx_token": "influx-secret-value"},
        "auth": {
            "enabled": True,
            "session_secret": "sess-secret-value",
            "ldap": {
                "server": "ldaps://dc.example.com",
                "bind_dn": "cn=svc,dc=example,dc=com",
                "bind_password": "ldap-secret-value",
            },
        },
        "clusters": [{
            "id": "c1", "name": "prod", "nodes": [{"host": "10.0.0.10"}],
            "auth": {"user": "monitoring@pve",
                     "token_name": "jt", "token_value": "tok-secret-value"},
        }],
    })
    return c.to_dict()


# ---------------------------------------------------------------- masking

@pytest.mark.parametrize("secret", [
    "influx-secret-value",
    "sess-secret-value",
    "ldap-secret-value",
    "tok-secret-value",
])
def test_no_secret_value_survives_masking(secret, monkeypatch):
    monkeypatch.setattr(srv.secret_store, "has_secret", lambda *a, **kw: False)
    blob = repr(srv._mask_config_secrets(_full_config_dict()))
    assert secret not in blob, f"{secret!r} was returned verbatim"


def test_masking_keeps_the_configured_signal(monkeypatch):
    """The UI decides on presence, so an unset secret must stay distinguishable
    from a set one -- HoloMatrix keys the console prompt off exactly this."""
    monkeypatch.setattr(srv.secret_store, "has_secret", lambda *a, **kw: False)
    masked = srv._mask_config_secrets(_full_config_dict())
    assert masked["clusters"][0]["auth"]["token_value"] == "***"
    assert masked["server"]["influx_token"] == "***"

    empty = cfg_mod.Config.from_dict(
        {"clusters": [{"id": "c1", "nodes": [], "auth": {}}]}).to_dict()
    masked_empty = srv._mask_config_secrets(empty)
    assert masked_empty["clusters"][0]["auth"]["token_value"] == ""
    assert masked_empty["server"]["influx_token"] == ""


def test_unknown_ldap_credential_keys_are_masked(monkeypatch):
    """auth.ldap is schema-less on purpose, so masking goes by key name."""
    monkeypatch.setattr(srv.secret_store, "has_secret", lambda *a, **kw: False)
    d = cfg_mod.Config.from_dict({"auth": {"ldap": {
        "tls_key": "pem-value", "some_token": "tok", "bind_dn": "cn=x"}}}).to_dict()
    masked = srv._mask_config_secrets(d)
    assert masked["auth"]["ldap"]["tls_key"] == "***"
    assert masked["auth"]["ldap"]["some_token"] == "***"
    assert masked["auth"]["ldap"]["bind_dn"] == "cn=x", "non-secret was clobbered"


# ---------------------------------------------------------------- viewer scope

def test_viewer_projection_drops_infrastructure_detail(monkeypatch):
    monkeypatch.setattr(srv.secret_store, "has_secret", lambda *a, **kw: False)
    masked = srv._mask_config_secrets(_full_config_dict())
    view = srv._project_config_for_viewer(masked)

    assert "auth" not in view, "auth block reached a viewer"
    assert "server" not in view, "bind address / influx settings reached a viewer"
    assert "nodes" not in view["clusters"][0], "node addresses reached a viewer"
    assert "user" not in view["clusters"][0]["auth"], "PVE username reached a viewer"


def test_viewer_projection_keeps_what_the_spa_needs(monkeypatch):
    """App.tsx reads ui.*, RadarScan/HoloMatrix read console.mode, and
    HoloMatrix keys the console prompt off clusters[].auth.password."""
    monkeypatch.setattr(srv.secret_store, "has_secret", lambda *a, **kw: False)
    view = srv._project_config_for_viewer(srv._mask_config_secrets(_full_config_dict()))
    assert "ui" in view and "alerts" in view
    assert view["console"]["mode"] in ("disabled", "stored", "prompt")
    assert view["clusters"][0]["id"] == "c1"
    assert view["clusters"][0]["name"] == "prod"
    assert "password" in view["clusters"][0]["auth"]


def test_no_secret_survives_the_viewer_projection(monkeypatch):
    monkeypatch.setattr(srv.secret_store, "has_secret", lambda *a, **kw: False)
    blob = repr(srv._project_config_for_viewer(
        srv._mask_config_secrets(_full_config_dict())))
    for secret in ("influx-secret-value", "sess-secret-value",
                   "ldap-secret-value", "tok-secret-value"):
        assert secret not in blob
