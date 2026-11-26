# localhost-guard

Your service listens on `127.0.0.1`, so it needs no login. Every page you visit
can still POST to it.

```
POST http://127.0.0.1:8765/api/quit HTTP/1.1
Origin: https://evil.example
Content-Type: text/plain

```

The browser sends it, your handler runs, the app exits. The port is not a secret
— a page can scan 8000–9000 in a second — and the request is indistinguishable
from the one your own UI issues. This is "drive-by localhost", and it works on
desktop shells, dev servers and anything else with a loopback HTTP API.

`localhost-guard` is the set of header checks that stops it, small enough to
paste into an existing `BaseHTTPRequestHandler`.

## Install

```bash
pip install localhost-guard
```

## Use

```python
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from localhost_guard import LoopbackOnly

class Handler(LoopbackOnly, BaseHTTPRequestHandler):
    def do_GET(self):
        if not self.guard():
            return                      # response already written: 403 or 415
        self.reply({"ok": True})

    def do_POST(self):
        if not self.guard():
            return
        ...
```

Or call the pure function when you have your own framework:

```python
from localhost_guard import check

decision = check("POST", request.headers)
if not decision.allowed:
    return Response(decision.reason, status=decision.status)
```

## The four checks

| Header | Refuse when | Stops |
| --- | --- | --- |
| `Host` | not `127.0.0.1`, `localhost`, `[::1]`, or empty/missing on a write | DNS rebinding |
| `Sec-Fetch-Site` | `cross-site` (when present) | another page's request |
| `Origin` | not loopback, or `null` | cross-origin `fetch`/form posts |
| `Content-Type` | write without `application/json` | cross-origin form posts |

No single check is enough. `Sec-Fetch-*` is missing from older browsers, `Origin`
is omitted on same-origin GETs, and a cross-origin `fetch` with
`Content-Type: application/json` triggers a preflight your service never answers
— so it never arrives. That last one is why `require_json` is on by default for
writes: an HTML form cannot send that media type, so the drive-by request fails
before your handler sees it.

`trusted_origins` exists for the case where your own UI is served from a real
host during development:

```python
class Handler(LoopbackOnly, BaseHTTPRequestHandler):
    trusted_origins = ("https://demo.example",)
```

## What this does not cover

- **GET is always allowed.** A cross-site page can still trigger a GET to
  `http://127.0.0.1:PORT/...`, because reads need no preflight and no CORS
  approval. Never put a state change behind GET (`/delete?id=`, `/sync`,
  `/switch-profile`) — that endpoint is unprotected no matter what this library
  does. Either keep every mutation on POST/PUT/PATCH/DELETE, or call
  `guard(write=True)` in that handler so the write rules apply to it anyway
  (that flag reaches `check()`; the Host and Content-Type rules then apply even
  though the method is `GET`). Note the Content-Type half: a navigation-style
  `GET` (`<a href="/delete?id=1">`) carries no `Content-Type`, so with the
  default `require_json=True` it is rejected with **415** — safe, but it kills
  the link. Pair the flag with `require_json = False` on the handler unless the
  caller is scripted enough to send JSON:

  ```python
  class Handler(LoopbackOnly, BaseHTTPRequestHandler):
      require_json = False          # GET links carry no Content-Type
      def do_GET(self):
          if not self.guard(write=True):
              return
          ...                       # Host + Sec-Fetch-Site still enforced
  ```
- **It is a function, not middleware.** Every handler has to call it; one handler
  that forgets is one unguarded endpoint, silently. If you want it enforced
  structurally, wrap your framework's dispatcher so a response cannot be produced
  without a `Decision`.
- **`require_json=True` rejects file uploads.** `multipart/form-data` and
  `fetch(..., body: new FormData())` get 415 by design; pass `require_json=False`
  on upload routes and lean on `Sec-Fetch-Site` there.
- A local process running as another user on the same machine can send whatever
  headers it likes. This is a browser-threat model, not an OS one.
- It does not replace authentication if the service is ever bound to a
  non-loopback interface.
- **A write with no `Host` header is rejected, not trusted.** An empty or missing
  `Host` is not loopback: it means something other than a browser reached you, so
  the request gets 403. Reads without a `Host` are allowed, which keeps `curl
  http://127.0.0.1:PORT/` working.

## Scope and non-goals

- **Not a framework integration.** Flask/Django/FastAPI adapters are out of scope;
  the package is one zero-dependency module you copy or import.
- **Not CSRF tokens.** There is no session, no token store, no cookie — the checks
  are header-based (Host, `Sec-Fetch-Site`, Origin, and a JSON content type on
  writes). If you need per-session tokens, add them; this is the cheap floor.
- **Not protection against local processes.** Anything running as another user on
  the same box can forge headers. That is the browser threat model's edge.

## Status

0.1.3 — on PyPI (`pip install localhost-guard`); 0.1.1 and 0.1.0 are yanked.
0.1.1 silently ignored `guard(write=True)` on `GET`; 0.1.0 additionally carried
the pre-release README. 0.1.3 only documents that `write=True` plus the default
`require_json=True` rejects navigation-style GETs with 415, so the two flags go
together. Trusted Publishing (OIDC) does the upload,
so no token lives in this repository. Tags (`v*`) build sdist + wheel and attach
them to the GitHub release.

## Tests

```bash
python -m pytest -q
```

Nineteen cases: the unit checks, plus a real `ThreadingHTTPServer` on an ephemeral
port to prove the mixin writes 403 for a cross-site POST and 415 for a form post.

## Licence

MIT.
