import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import security_audit as sa


def test_rating_boundaries():
    assert sa.rate(5) == "Low"
    assert sa.rate(6) == "Medium"
    assert sa.rate(12) == "High"
    assert sa.rate(20) == "Critical"


def test_plain_http_is_flagged():
    findings = sa.analyze_response("http://example.test", [])
    assert any(f.check == "HTTPS" for f in findings)


def test_hardened_https_response_has_no_findings():
    headers = [
        ("Strict-Transport-Security", "max-age=31536000"),
        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ("Permissions-Policy", "camera=()"),
        ("Set-Cookie", "sid=abc; Secure; HttpOnly; SameSite=Lax"),
    ]
    assert sa.analyze_response("https://example.test", headers) == []


def test_weak_cookie_and_banner_are_flagged():
    headers = [("Server", "Apache/2.4.1"), ("Set-Cookie", "sid=abc")]
    checks = {f.check for f in sa.analyze_response("https://example.test", headers)}
    assert "Information disclosure" in checks
    assert "Cookie flags (sid)" in checks


def test_findings_sorted_by_score_descending():
    findings = sa.analyze_response("http://example.test", [])
    scores = [f.score for f in findings]
    assert scores == sorted(scores, reverse=True)


class _Insecure(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Server", "Apache/2.4.1")
        self.send_header("Set-Cookie", "sid=abc")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


@pytest.fixture
def local_server():
    server = HTTPServer(("127.0.0.1", 0), _Insecure)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_end_to_end_against_local_server(local_server, tmp_path):
    final_url, headers = sa.fetch(local_server)
    findings = sa.analyze_response(final_url, headers)
    assert any(f.check == "HTTPS" for f in findings)
    assert any(f.check == "Content-Security-Policy" for f in findings)
    out = tmp_path / "register.csv"
    sa.to_csv(out, findings)
    assert out.read_text().startswith("rating,score,check")


def test_cli_refuses_without_confirmation(capsys):
    assert sa.main(["http://127.0.0.1"]) == 2
    assert "confirm-authorized" in capsys.readouterr().err
