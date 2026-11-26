"""Reject cross-origin requests to a service that listens on loopback.

A local HTTP API has no login, because it is only reachable from your machine.
That reasoning is wrong: any web page you visit can send requests to
``http://127.0.0.1:<port>/`` — the browser will happily POST there, and the
service cannot tell the difference from a request its own UI made. Attackers
call it "drive-by localhost": the page probes a list of common ports and issues
``POST /api/quit``, ``/api/shutdown``, ``/api/export`` and so on.

The port is not secret (the attacker can scan), so the defence has to be a
header check the browser will not let the page forge:

* ``Host`` — the service only answers to loopback names, which stops DNS
  rebinding;
* ``Sec-Fetch-Site`` — ``cross-site`` is what another page's request looks like,
  and pages cannot set it;
* ``Origin`` — for requests that carry it, refuse anything that is not loopback;
* ``Content-Type`` — a cross-origin HTML form can only send urlencoded,
  multipart or text/plain. A service that demands ``application/json`` is not
  reachable that way, because that media type requires a CORS preflight.

No single check is sufficient on its own, which is why all four are here: older
browsers omit ``Sec-Fetch-*``, and ``Origin`` is missing from same-origin GETs.
"""

from __future__ import annotations

from typing import Iterable, Mapping, Optional

__all__ = ["Decision", "check", "LoopbackOnly"]

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "[::1]", "::1"})
SAFE_SITES = frozenset({"same-origin", "same-site", "none"})
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
JSON_CONTENT_TYPE = "application/json"


class Decision:
    """Outcome of a check: allowed, or refused with a reason for the log."""

    __slots__ = ("allowed", "status", "reason")

    def __init__(self, allowed: bool, status: int = 200, reason: str = "") -> None:
        self.allowed = allowed
        self.status = status
        self.reason = reason

    def __bool__(self) -> bool:
        return self.allowed

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Decision(allowed={self.allowed!r}, status={self.status!r}, reason={self.reason!r})"


_ALLOW = Decision(True)


def _host_port(host_header: str) -> str:
    host = host_header.strip().lower()
    if host.startswith("["):                 # [::1]:8080
        end = host.find("]")
        return host[: end + 1] if end != -1 else host
    return host.split(":", 1)[0]


def check(method: str,
          headers: Mapping[str, str],
          *,
          trusted_origins: Iterable[str] = (),
          require_json: bool = True) -> Decision:
    """Decide whether a request may touch the service.

    ``headers`` is case-insensitive in practice; pass the request headers as a
    plain mapping and the lookup below lower-cases both sides.
    """
    lowered = {k.lower(): v for k, v in headers.items()}
    host = _host_port(lowered.get("host", ""))
    if not host:
        # No Host at all: HTTP/1.0, or something in the middle stripped it. A
        # browser always sends one, so a write without it is not a browser we
        # want to serve; a read is harmless and keeps old clients working.
        if method.upper() in WRITE_METHODS:
            return Decision(False, 403, "write without a Host header")
        return _ALLOW
    if host not in LOOPBACK_HOSTS:
        return Decision(False, 403, f"host not loopback: {lowered.get('host')!r}")

    site = lowered.get("sec-fetch-site", "")
    if site and site not in SAFE_SITES:
        return Decision(False, 403, f"cross-site request: sec-fetch-site={site!r}")

    origin = lowered.get("origin", "")
    if origin:
        # A page loaded from file:// (or a sandboxed frame) sends "null"; treat it
        # like any other stranger. Everything else only counts when it is loopback.
        if origin == "null":
            return Decision(False, 403, "opaque origin")
        if origin.rstrip("/") not in {o.rstrip("/") for o in trusted_origins}:
            origin_host = _host_port(origin.split("://", 1)[-1])
            if origin_host not in LOOPBACK_HOSTS:
                return Decision(False, 403, f"untrusted origin: {origin!r}")

    if require_json and method.upper() in WRITE_METHODS:
        ctype = lowered.get("content-type", "").split(";", 1)[0].strip().lower()
        if ctype != JSON_CONTENT_TYPE:
            return Decision(False, 415, f"write requires application/json, got {ctype!r}")

    return _ALLOW


class LoopbackOnly:
    """Mixin for :class:`http.server.BaseHTTPRequestHandler` subclasses.

    Subclass it first, then call :meth:`guard` at the top of ``do_GET`` and
    ``do_POST``::

        class Handler(LoopbackOnly, BaseHTTPRequestHandler):
            def do_POST(self):
                if not self.guard():
                    return
                ...

    When the request is refused, ``guard`` has already written the response.
    """

    trusted_origins: tuple[str, ...] = ()
    require_json: bool = True

    def guard(self, *, write: Optional[bool] = None) -> bool:
        method = getattr(self, "command", "GET")
        if write is None:
            write = method.upper() in WRITE_METHODS
        decision = check(method, self.headers, trusted_origins=self.trusted_origins,
                         require_json=write and self.require_json)
        if decision.allowed:
            return True
        self.send_response(decision.status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("X-Guard-Reason", decision.reason)
        self.end_headers()
        try:
            self.wfile.write(decision.reason.encode("utf-8", "replace"))
        except Exception:                    # peer already gone
            pass
        return False
