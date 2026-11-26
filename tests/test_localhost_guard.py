from __future__ import annotations

import http.client
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from localhost_guard import Decision, LoopbackOnly, check


def test_plain_loopback_get_is_allowed():
    assert check("GET", {"Host": "127.0.0.1:8080"}).allowed


def test_localhost_and_empty_host_allowed():
    assert check("GET", {"Host": "localhost:9"}).allowed
    assert check("GET", {}).allowed


def test_rebinding_host_is_rejected():
    d = check("GET", {"Host": "evil.example:8080"})
    assert not d.allowed and d.status == 403


def test_cross_site_post_is_rejected():
    d = check("POST", {"Host": "127.0.0.1:8080", "Sec-Fetch-Site": "cross-site",
                       "Content-Type": "application/json"})
    assert not d.allowed and "cross-site" in d.reason


def test_same_origin_post_with_json_is_allowed():
    d = check("POST", {"Host": "127.0.0.1:8080", "Sec-Fetch-Site": "same-origin",
                       "Content-Type": "application/json"})
    assert d.allowed


def test_foreign_origin_is_rejected():
    d = check("POST", {"Host": "127.0.0.1:8080", "Origin": "https://evil.example",
                       "Content-Type": "application/json"})
    assert not d.allowed and d.status == 403


def test_loopback_origin_allowed_and_trusted_origin_can_be_added():
    assert check("POST", {"Host": "127.0.0.1:8080", "Origin": "http://localhost:5173",
                          "Content-Type": "application/json"}).allowed
    assert check("POST", {"Host": "127.0.0.1:8080", "Origin": "https://demo.example",
                          "Content-Type": "application/json"},
                 trusted_origins=("https://demo.example",)).allowed


def test_opaque_origin_rejected():
    assert not check("POST", {"Host": "127.0.0.1:1", "Origin": "null",
                              "Content-Type": "application/json"}).allowed


def test_form_encoded_post_rejected():
    d = check("POST", {"Host": "127.0.0.1:8080", "Content-Type": "application/x-www-form-urlencoded"})
    assert not d.allowed and d.status == 415


def test_form_encoded_post_allowed_when_json_not_required():
    assert check("POST", {"Host": "127.0.0.1:8080",
                          "Content-Type": "application/x-www-form-urlencoded"},
                 require_json=False).allowed


def test_json_with_charset_is_accepted():
    assert check("POST", {"Host": "127.0.0.1:8080",
                          "Content-Type": "application/json; charset=utf-8"}).allowed


def test_decision_is_falsy_when_denied():
    assert not Decision(False)
    assert Decision(True)


# --- end to end: a real server behind the mixin -------------------------------


class _Handler(LoopbackOnly, BaseHTTPRequestHandler):
    def do_GET(self):
        if not self.guard():
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        if not self.guard():
            return
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):  # keep test output clean
        pass


@pytest.fixture()
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def _request(port, method, headers=None, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, "/api", body=body, headers=headers or {})
        response = conn.getresponse()
        return response.status, response.read(), dict(response.getheaders())
    finally:
        conn.close()


def test_server_allows_same_origin_post(server):
    status, body, _ = _request(server, "POST",
                               {"Content-Type": "application/json",
                                "Sec-Fetch-Site": "same-origin"}, b"{}")
    assert status == 200 and body == b"ok"


def test_server_refuses_cross_site_post(server):
    status, body, headers = _request(server, "POST",
                                     {"Content-Type": "application/json",
                                      "Sec-Fetch-Site": "cross-site"}, b"{}")
    assert status == 403
    assert "cross-site" in headers.get("X-Guard-Reason", "")
    assert body  # the reason is written to the client too


def test_server_refuses_form_post(server):
    status, _, headers = _request(server, "POST",
                                  {"Content-Type": "application/x-www-form-urlencoded"},
                                  b"a=1")
    assert status == 415
    assert "application/json" in headers.get("X-Guard-Reason", "")


def test_server_allows_plain_get(server):
    status, body, _ = _request(server, "GET")
    assert status == 200 and body == b"ok"

def test_write_without_host_header_is_refused():
    d = check("POST", {"content-type": "application/json"}, )
    assert not d and d.status == 403
    assert "Host" in d.reason


def test_read_without_host_header_is_allowed():
    assert check("GET", {})


def test_empty_host_string_is_not_loopback():
    d = check("POST", {"host": "", "content-type": "application/json"})
    assert not d and d.status == 403
