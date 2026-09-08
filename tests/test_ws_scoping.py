"""The WebSocket carries the entire product: every cluster, node, guest and
storage. It was gated on "are you logged in?" and nothing else, so a session
with no role grant at all received all of it on connect and on every poll.
"""
from __future__ import annotations

import json

import pytest

from server import auth
from server import server as srv


SNAPSHOT = {
    "clusters": {
        "cluster1": {"nodes": [{"node": "n1"}], "vms": {"n1/100": {}}},
        "cluster2": {"nodes": [{"node": "n9"}], "vms": {"n9/900": {}}},
        "cluster3": {"nodes": [], "vms": {}},
    },
    "timestamp": 1.0,
}


@pytest.fixture
def known_clusters(monkeypatch):
    """_visible_cluster_ids enumerates what the manager knows about."""
    monkeypatch.setattr(srv.cluster_manager, "clusters",
                        {"cluster1": object(), "cluster2": object(), "cluster3": object()},
                        raising=False)
    monkeypatch.setattr(srv.cluster_manager, "adapters", {}, raising=False)


# ------------------------------------------------------------------ scoping

def test_auth_disabled_sees_everything(known_clusters):
    """Backward-compat policy: user is None when auth is off."""
    assert srv._visible_cluster_ids(None) is None


def test_global_grant_sees_everything(db_path, known_clusters):
    uid = auth.create_user("ga", "Passw0rd-Test!")
    auth.grant_role("ga", "*", "viewer")
    user = {"id": uid, "role_global": "viewer"}
    assert srv._visible_cluster_ids(user) is None


def test_cluster_grant_sees_only_that_cluster(db_path, known_clusters):
    uid = auth.create_user("c1", "Passw0rd-Test!")
    auth.grant_role("c1", "cluster1", "viewer")
    user = {"id": uid, "role_global": None}
    assert srv._visible_cluster_ids(user) == frozenset({"cluster1"})


def test_no_grant_sees_nothing(db_path, known_clusters):
    uid = auth.create_user("nada", "Passw0rd-Test!")
    user = {"id": uid, "role_global": None}
    assert srv._visible_cluster_ids(user) == frozenset()


# ------------------------------------------------------------------ filtering

def test_snapshot_is_filtered_to_scope():
    out = srv._scope_snapshot(SNAPSHOT, frozenset({"cluster1"}))
    assert set(out["clusters"]) == {"cluster1"}
    assert out["timestamp"] == 1.0, "non-cluster fields must survive"


def test_empty_scope_yields_no_clusters():
    out = srv._scope_snapshot(SNAPSHOT, frozenset())
    assert out["clusters"] == {}


def test_none_scope_is_passthrough():
    assert srv._scope_snapshot(SNAPSHOT, None) is SNAPSHOT


def test_no_data_from_an_invisible_cluster_survives():
    """Not just the key -- nothing about node n9 or vm 900 may appear."""
    blob = json.dumps(srv._scope_snapshot(SNAPSHOT, frozenset({"cluster1"})))
    assert "cluster2" not in blob
    assert "n9" not in blob and "900" not in blob


# ------------------------------------------------------------------ broadcast

@pytest.mark.asyncio
async def test_broadcast_sends_each_client_only_its_own_scope(monkeypatch):
    sent: dict = {}

    class _WS:
        def __init__(self, name, scope):
            self._name = name
            self._jtp_scope = scope
        async def send_str(self, msg):
            sent[self._name] = json.loads(msg)

    everything = _WS("all", None)
    only1 = _WS("one", frozenset({"cluster1"}))
    nothing = _WS("none", frozenset())

    monkeypatch.setattr(srv, "ws_clients", {everything, only1, nothing})
    monkeypatch.setattr(srv, "_last_broadcast_hash", 0)

    await srv.broadcast_to_clients(SNAPSHOT)

    assert set(sent["all"]["data"]["clusters"]) == {"cluster1", "cluster2", "cluster3"}
    assert set(sent["one"]["data"]["clusters"]) == {"cluster1"}
    assert sent["none"]["data"]["clusters"] == {}


@pytest.mark.asyncio
async def test_one_serialisation_per_distinct_scope(monkeypatch):
    """Filtering must not turn one JSON encode into one-per-client: three
    viewers of the same cluster are one scope."""
    calls = {"n": 0}
    real_dumps = srv.json.dumps

    def counting_dumps(obj, **kw):
        calls["n"] += 1
        return real_dumps(obj, **kw)

    class _WS:
        def __init__(self, scope):
            self._jtp_scope = scope
        async def send_str(self, msg):
            pass

    scope = frozenset({"cluster1"})
    monkeypatch.setattr(srv, "ws_clients", {_WS(scope), _WS(scope), _WS(scope)})
    monkeypatch.setattr(srv, "_last_broadcast_hash", 0)
    monkeypatch.setattr(srv.json, "dumps", counting_dumps)

    await srv.broadcast_to_clients(SNAPSHOT)
    # hash + full message + one scoped message = 3. Four would mean per-client.
    assert calls["n"] <= 3, f"serialised {calls['n']} times for one scope"
