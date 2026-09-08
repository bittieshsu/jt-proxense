"""aiohttp middleware + route decorators for jt-proxense v0.2+.

Behaviour matrix:

  config.auth.enabled = false (DEFAULT — v0.1 compat)
    middleware passes through.   request["user"] = None.
    decorators are no-ops.

  config.auth.enabled = true
    middleware resolves the `jtps` cookie -> session -> user.
    request["user"] = {"id":..., "username":..., "role_global":...} or None.
    Routes flagged @auth_required reject with 401 when user is None.
    Routes flagged @role_required("admin") reject with 403 when role insufficient.

Each request also gets a 12-char correlation id at request["request_id"], echoed
back as the X-Request-Id header. The audit module reads it from there.
"""
from __future__ import annotations

import functools
import ipaddress
import logging
import secrets
from typing import Awaitable, Callable, Optional

from aiohttp import web

from . import auth as auth_mod
from . import config as config_mod

logger = logging.getLogger(__name__)

# Routes that MUST work even without a session (login itself, static assets).
# Anything else is gated when auth is enabled.
_PUBLIC_PATHS = {
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/me",          # frontend uses this to discover "am I logged in?"
    "/api/auth/totp/login",  # 2FA second factor — no session yet at this point
    "/api/health",           # liveness probe — no telemetry
}
_PUBLIC_PREFIXES = (
    "/assets/",
    "/fonts/",
    "/login",            # the login page HTML itself
)


def _is_public(path: str) -> bool:
    if path in _PUBLIC_PATHS:
        return True
    if path == "/login":
        return True
    if path == "/favicon.svg":
        return True
    return any(path.startswith(p) for p in _PUBLIC_PREFIXES)


def _role_rank(role: Optional[str]) -> int:
    return {"viewer": 1, "operator": 2, "admin": 3}.get(role or "", 0)


# Peers we have already warned about sending an untrusted XFF. Bounded by
# the number of distinct direct peers, which is small in every real
# deployment; cleared only by a restart.
_XFF_IGNORED_SEEN: set = set()


def _is_trusted_proxy(remote: Optional[str]) -> bool:
    """Is the immediate peer allowed to set X-Forwarded-For?

    Loopback only, plus whatever `auth.trusted_proxies` names.

    This used to trust every RFC1918, link-local and loopback peer implicitly,
    on the reasoning that "reverse proxies sit on the private LAN". The
    realistic attacker against an internal tool is already ON that LAN, and
    trusting them means the value they put in X-Forwarded-For becomes the
    identity used for the per-IP login lockout and written into the audit log
    as the source of every action -- so the rate limiter can be walked straight
    past with a fresh header value, and the audit trail can be pointed at
    someone else. The reverse-proxy-on-the-same-host case (the documented
    deployment, nginx terminating TLS in front of 127.0.0.1:8098) still works
    untouched; a proxy on another machine must now be named.
    """
    if not remote:
        return False
    try:
        ip = ipaddress.ip_address(remote)
    except ValueError:
        return False
    if ip.is_loopback:
        return True
    try:
        trusted = config_mod.get_config().auth.trusted_proxies or []
    except Exception:
        trusted = []
    for entry in trusted:
        try:
            if ip in ipaddress.ip_network(str(entry), strict=False):
                return True
        except ValueError:
            if remote == str(entry):
                return True
    return False


def _client_ip(request: web.Request) -> str:
    """Client IP for rate-limiting + audit. X-Forwarded-For is honored ONLY
    when the immediate peer is a trusted proxy — otherwise a direct public
    client could spoof XFF to dodge the per-IP login lockout."""
    remote = request.remote or "unknown"
    xff = request.headers.get("X-Forwarded-For")
    if xff and _is_trusted_proxy(remote):
        return xff.split(",")[0].strip()
    if xff:
        # Say so once per peer. An operator who moved their reverse proxy off
        # this host would otherwise see every audit row and every rate-limit
        # decision quietly attributed to the proxy, with nothing explaining why.
        if remote not in _XFF_IGNORED_SEEN:
            _XFF_IGNORED_SEEN.add(remote)
            logger.warning(
                "ignoring X-Forwarded-For from %s: not a trusted proxy. If this "
                "is your reverse proxy, add it to auth.trusted_proxies -- until "
                "then rate limiting and audit records use %s itself.",
                remote, remote)
    return remote


# ---------------------------------------------------------------- middleware

@web.middleware
async def request_id_middleware(request: web.Request, handler):
    request["request_id"] = secrets.token_urlsafe(9)  # 12 chars
    request["client_ip"] = _client_ip(request)
    response = await handler(request)
    response.headers["X-Request-Id"] = request["request_id"]
    return response


# Content-Security-Policy. Everything is same-origin: the SPA loads its bundle
# from /assets, fonts from /fonts, talks to the API + WebSocket on the same
# origin. script-src uses a PER-REQUEST NONCE (no 'unsafe-inline') — every
# inline <script> we emit (the SPA index self-heal + the server-rendered
# login / console / account / … pages) stamps the same nonce via
# request["csp_nonce"] / csp_nonce(request). style-src keeps 'unsafe-inline'
# because the React components emit inline <style> at runtime (client-side,
# can't be nonced); styles can't execute JS so the residual risk is low.
def _build_csp(nonce: str) -> str:
    return (
        "default-src 'self'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "font-src 'self'; "
        # 'self' already covers same-origin ws:// / wss:// under CSP3.
        "connect-src 'self'; "
        "form-action 'self'"
    )


def csp_nonce(request: web.Request) -> str:
    """The per-request CSP nonce for inline <script nonce="..."> tags."""
    return request.get("csp_nonce", "")


_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    # Cross-origin isolation: keep the app in its own browsing-context group and
    # forbid other origins from embedding our resources (defence-in-depth vs
    # Spectre-style side channels and resource theft). Same-origin only, so
    # nothing legitimately loaded is cross-origin.
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    # Don't leak the aiohttp/Python version.
    "Server": "jt-proxense",
}


def _is_https(request: web.Request) -> bool:
    if request.scheme == "https":
        return True
    fwd = request.headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower()
    return fwd == "https"


@web.middleware
async def security_headers_middleware(request: web.Request, handler):
    """Stamp common security headers (incl. a nonce-based CSP) on every response.

    A fresh CSP nonce is generated per request and exposed as
    request["csp_nonce"] so the handlers that emit inline <script> can stamp
    <script nonce="..."> — that lets script-src drop 'unsafe-inline'.

    HSTS is added only when the request was served over HTTPS (direct or
    via X-Forwarded-Proto). Sending Strict-Transport-Security over HTTP
    is meaningless and wastes bytes.
    """
    nonce = secrets.token_urlsafe(16)
    request["csp_nonce"] = nonce
    extra = {"Content-Security-Policy": _build_csp(nonce)}
    if _is_https(request):
        extra["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    try:
        response = await handler(request)
    except web.HTTPException as e:
        for k, v in _SECURITY_HEADERS.items():
            e.headers.setdefault(k, v)
        for k, v in extra.items():
            e.headers.setdefault(k, v)
        e.headers["Server"] = "jt-proxense"
        raise
    for k, v in _SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    for k, v in extra.items():
        response.headers.setdefault(k, v)
    # aiohttp stamps its own "Server: Python/x aiohttp/y"; overwrite it (a
    # plain setdefault above won't win against a header aiohttp already set).
    response.headers["Server"] = "jt-proxense"
    # Stamp the CSP nonce onto every inline <script> in HTML responses (SPA
    # index + all server-rendered pages), so script-src can stay nonce-based
    # with no 'unsafe-inline'. Only plain web.Response bodies are rewritten
    # (FileResponse/StreamResponse stream and have no in-memory body).
    if (isinstance(response, web.Response) and response.body is not None
            and "text/html" in response.headers.get("Content-Type", "")):
        try:
            body = response.text
            if body and "<script>" in body:
                response.text = body.replace("<script>", f'<script nonce="{nonce}">')
        except (UnicodeDecodeError, TypeError):
            pass
    return response


def make_auth_middleware(auth_enabled: bool):
    """Closes over the config flag so we can switch behaviour at startup time
    without an extra dict lookup per request."""
    @web.middleware
    async def auth_middleware(request: web.Request, handler):
        if not auth_enabled:
            request["user"] = None
            return await handler(request)

        sid = request.cookies.get(auth_mod.SESSION_COOKIE)
        session = await auth_mod.get_session(sid) if sid else None
        request["user"] = None
        if session:
            user_row = auth_mod.get_user_by_id(session.user_id)
            if user_row and user_row["enabled"]:
                request["user"] = {
                    "id": user_row["id"],
                    "username": user_row["username"],
                    "session_id": session.id,
                    "role_global": auth_mod.role_for(user_row["id"], "*"),
                }

        if request["user"] is None and not _is_public(request.path):
            # API calls get JSON 401; HTML routes get a redirect to /login.
            if request.path.startswith("/api/") or request.path == "/ws":
                return web.json_response(
                    {"error": "auth_required", "message": "login required"},
                    status=401,
                )
            raise web.HTTPFound("/login")
        return await handler(request)
    return auth_middleware


# ---------------------------------------------------------------- decorators

def auth_required(handler: Callable[..., Awaitable]):
    """Reject 401 when auth is enabled and no user. No-op when auth is disabled
    (middleware sets request["user"] = None and passes through)."""
    @functools.wraps(handler)
    async def wrapped(request: web.Request, *a, **kw):
        # If auth is disabled, request["user"] is None and we pass through.
        # If auth is enabled, the global middleware already 401'd anonymous
        # requests; if we reach here, request["user"] is set.
        return await handler(request, *a, **kw)
    return wrapped


def effective_role(request: web.Request) -> Optional[str]:
    """The caller's role AGAINST THE THING THIS REQUEST TARGETS.

    Grants are `(user, cluster_id|*) -> role` and `auth.role_for()` already
    resolves them correctly: it matches rows for the named cluster *and* rows
    scoped to `*`, then returns the highest rank. What was missing is that
    role_required() never asked -- it read `role_global`, which is literally
    `role_for(user, "*")`, so a per-cluster grant was invisible to it.

    The effect was a permission model that read as "per-cluster" in the README
    and the CLI, and behaved as "global only" at the door: a user granted
    `cluster1 operator` and nothing else had `role_global = None`, rank 0, and
    was refused by every decorated endpoint on the cluster they were explicitly
    given. VM-level handlers were fine, because those call `_check_vm_role()`,
    which does pass the cluster through -- two authorization systems, one
    right.

    Routes that name no cluster (`/api/users`, `/api/config`, `/api/audit`)
    still resolve against `*` only, so a cluster-scoped admin does not become a
    global one.
    """
    user = request.get("user")
    if user is None:
        return None
    cluster_id = request.match_info.get("cluster_id")
    user_id = user.get("id")
    if cluster_id and user_id is not None:
        return auth_mod.role_for(user_id, cluster_id)
    # No cluster in the path, or a caller that carries no user id (the auth
    # middleware always sets one; test doubles and any future synthetic request
    # may not). Fall back to the global grant -- which is what this function
    # returned for every request before, so the fallback can only ever be
    # narrower than a cluster-scoped lookup, never wider.
    return user.get("role_global")


def role_required(min_role: str):
    """Reject 403 when the user's role for this request's target is below
    `min_role`. No-op if auth disabled. See effective_role()."""
    needed = _role_rank(min_role)
    if needed == 0:
        raise ValueError(f"unknown role: {min_role}")

    def deco(handler):
        @functools.wraps(handler)
        async def wrapped(request: web.Request, *a, **kw):
            user = request.get("user")
            if user is None:
                # auth disabled -> permit (matches v0.1 behaviour)
                return await handler(request, *a, **kw)
            if _role_rank(effective_role(request)) >= needed:
                return await handler(request, *a, **kw)
            return web.json_response(
                {"error": "forbidden", "required_role": min_role},
                status=403,
            )
        return wrapped
    return deco
