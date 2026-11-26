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
| `Host` | not `127.0.0.1`, `localhost`, `[::1]`, empty | DNS rebinding |
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

- A local process running as another user on the same machine can send whatever
  headers it likes. This is a browser-threat model, not an OS one.
- It does not replace authentication if the service is ever bound to a
  non-loopback interface.

## Tests

```bash
python -m pytest -q
```

Sixteen cases: the unit checks, plus a real `ThreadingHTTPServer` on an ephemeral
port to prove the mixin writes 403 for a cross-site POST and 415 for a form post.

## Licence

MIT.
