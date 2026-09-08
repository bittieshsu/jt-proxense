"""Per-cluster RBAC, end to end at the door.

The grants table has always been `(user, cluster_id|*) -> role`, the CLI
advertises per-cluster grants, and `auth.role_for()` resolves them correctly.
role_required() simply never asked: it read `role_global`, which is literally
`role_for(user, "*")`. So a user granted `cluster1 operator` and nothing else
was refused by every decorated endpoint on the cluster they were given.
"""
from __future__ import annotations

import pytest
from aiohttp import web

from server import auth
from server import middleware as mw
from server.middleware import role_required, make_auth_middleware, request_id_middleware


@pytest.fixture
def users(db_path):
    """Three shapes of grant, and one user with none at all."""
    # grant_role() takes a USERNAME; create_user() returns an id.
    ids = {}
    ids["globaladmin"] = auth.create_user("globaladmin", "Passw0rd-Test!")
    auth.grant_role("globaladmin", "*", "admin")

    ids["c1op"] = auth.create_user("c1op", "Passw0rd-Test!")
    auth.grant_role("c1op", "cluster1", "operator")

    ids["c1viewer_c2admin"] = auth.create_user("mixed", "Passw0rd-Test!")
    auth.grant_role("mixed", "cluster1", "viewer")
    auth.grant_role("mixed", "cluster2", "admin")

    ids["nobody"] = auth.create_user("nobody", "Passw0rd-Test!")
    return ids


def _request(user_id, cluster_id=None):
    """Minimal stand-in: effective_role() reads request["user"] and match_info."""
    class _R:
        def __init__(self):
            self.match_info = {"cluster_id": cluster_id} if cluster_id else {}
            self._d = {"user": {"id": user_id,
                                "role_global": auth.role_for(user_id, "*")}}
        def get(self, k, default=None):
            return self._d.get(k, default)
    return _R()


# ------------------------------------------------------- the bug that was live

def test_cluster_scoped_grant_is_honoured(users):
    """`jt-proxense user grant bob cluster1 operator` must actually work on
    cluster1. This returned None (rank 0) before, i.e. 403 on every endpoint."""
    assert mw.effective_role(_request(users["c1op"], "cluster1")) == "operator"


def test_cluster_scoped_grant_does_not_leak_to_other_clusters(users):
    assert mw.effective_role(_request(users["c1op"], "cluster2")) is None


def test_highest_matching_grant_wins(users):
    u = users["c1viewer_c2admin"]
    assert mw.effective_role(_request(u, "cluster1")) == "viewer"
    assert mw.effective_role(_request(u, "cluster2")) == "admin"


def test_global_grant_still_covers_every_cluster(users):
    u = users["globaladmin"]
    assert mw.effective_role(_request(u, "cluster1")) == "admin"
    assert mw.effective_role(_request(u, "cluster9")) == "admin"


def test_no_grant_means_no_access(users):
    assert mw.effective_role(_request(users["nobody"], "cluster1")) is None
    assert mw.effective_role(_request(users["nobody"])) is None


# ------------------------------- a cluster admin must NOT become a global one

def test_cluster_admin_is_not_a_global_admin(users):
    """Routes that name no cluster (/api/users, /api/config, /api/audit)
    resolve against `*` only. Widening this would turn every cluster admin
    into a user administrator."""
    u = users["c1viewer_c2admin"]                 # admin on cluster2
    assert mw.effective_role(_request(u, "cluster2")) == "admin"
    assert mw.effective_role(_request(u)) is None, (
        "a cluster-scoped admin was treated as a global admin")


# ------------------------------------------------------------ through a handler

@pytest.mark.asyncio
async def test_decorator_allows_and_refuses_per_cluster(users, aiohttp_client,
                                                        monkeypatch):
    async def handler(request):
        return web.json_response({"ok": True})

    # Stand in for the auth middleware: pin a user onto the request. aiohttp
    # calls middlewares positionally, so the second parameter must be named
    # `handler` for its own signature check.
    uid = users["c1op"]

    @web.middleware
    async def fake_auth(request, handler):
        request["user"] = {"id": uid, "role_global": auth.role_for(uid, "*")}
        return await handler(request)

    app = web.Application(middlewares=[request_id_middleware, fake_auth])
    app.router.add_get("/api/clusters/{cluster_id}/thing",
                       role_required("operator")(handler))
    client = await aiohttp_client(app)

    r = await client.get("/api/clusters/cluster1/thing")
    assert r.status == 200, "operator on cluster1 was refused their own cluster"

    r = await client.get("/api/clusters/cluster2/thing")
    assert r.status == 403, "grant on cluster1 reached cluster2"
