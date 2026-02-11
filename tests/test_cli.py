import builtins
import http.client
import types
from datetime import datetime, timezone
from unittest.mock import Mock

import pytest
import requests

import certapi.cli as cli
from certapi.challenge_solver.InmemoryChallengeSolver import InMemoryChallengeSolver
from certapi.errors import CertApiException


class FakeKey:
    def to_pem(self):
        return "KEY"


class FakeKeyStore:
    def __init__(self, base_dir):
        self.keys_dir = f"{base_dir}/keys"
        self.certs_dir = f"{base_dir}/certs"
        self.saved = []

    def save_key(self, key, name):
        self.saved.append(("key", name))
        return "key-id"

    def save_cert(self, key_id, cert, domains, name=None):
        self.saved.append(("cert", name, tuple(domains)))
        return "cert-id"


class FakeAcmeCertIssuer:
    def __init__(self, key_store, solver, account_key_name):
        self.key_store = key_store
        self.solver = solver
        self.account_key_name = account_key_name
        self.setup_called = False
        self.raise_error = False

    @classmethod
    def with_keystore(cls, key_store, solver, account_key_name="acme_account"):
        return cls(key_store, solver, account_key_name)

    def setup(self):
        self.setup_called = True

    def generate_key_and_cert_for_domains(self, domains, key_type="rsa"):
        if self.raise_error:
            raise CertApiException("boom", {"reason": "bad"}, step="test")
        return FakeKey(), "CERT"


class FakeCert:
    def __init__(self, not_valid_after):
        self.not_valid_after = not_valid_after


def test_is_root_true_false(monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    assert cli.is_root() is True

    dummy_os = types.SimpleNamespace()
    monkeypatch.setattr(cli, "os", dummy_os)
    assert cli.is_root() is False


def test_find_process_on_port_success(monkeypatch):
    monkeypatch.setattr(cli.subprocess, "check_output", lambda *args, **kwargs: b"123\n456\n")
    assert cli.find_process_on_port(80) == ["123", "456"]


def test_find_process_on_port_empty(monkeypatch):
    monkeypatch.setattr(cli.subprocess, "check_output", lambda *args, **kwargs: b"")
    assert cli.find_process_on_port(80) == []


def test_find_process_on_port_error(monkeypatch):
    def raise_error(*args, **kwargs):
        raise cli.subprocess.CalledProcessError(1, "lsof")

    monkeypatch.setattr(cli.subprocess, "check_output", raise_error)
    assert cli.find_process_on_port(80) == []


def test_start_http_challenge_server_responses():
    solver = InMemoryChallengeSolver()
    solver.save_challenge("token-ok", "value", "example.com")
    solver.save_challenge("token-bytes", b"binary", "example.com")

    server, _ = cli._start_http_challenge_server(solver, port=0)
    try:
        port = server.server_address[1]

        conn = http.client.HTTPConnection("localhost", port)
        conn.request("GET", "/.well-known/acme-challenge/token-ok")
        response = conn.getresponse()
        data = response.read().decode("utf-8")
        assert response.status == 200
        assert data == "value"
        conn.close()

        conn = http.client.HTTPConnection("localhost", port)
        conn.request("GET", "/.well-known/acme-challenge/token-bytes")
        response = conn.getresponse()
        data = response.read().decode("utf-8")
        assert response.status == 200
        assert data == "binary"
        conn.close()

        conn = http.client.HTTPConnection("localhost", port)
        conn.request("GET", "/not-a-challenge")
        response = conn.getresponse()
        assert response.status == 404
        response.read()
        conn.close()

        conn = http.client.HTTPConnection("localhost", port)
        conn.request("GET", "/.well-known/acme-challenge/")
        response = conn.getresponse()
        assert response.status == 400
        response.read()
        conn.close()

        conn = http.client.HTTPConnection("localhost", port)
        conn.request("GET", "/.well-known/acme-challenge/missing")
        response = conn.getresponse()
        assert response.status == 404
        response.read()
        conn.close()
    finally:
        server.shutdown()
        server.server_close()


def test_resolve_cloudflare_api_key(monkeypatch):
    monkeypatch.delenv("CLOUDFLARE_API_KEY", raising=False)
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    assert cli._resolve_cloudflare_api_key() is None

    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "token")
    assert cli._resolve_cloudflare_api_key() == "token"

    monkeypatch.setenv("CLOUDFLARE_API_KEY", "key")
    assert cli._resolve_cloudflare_api_key() == "key"


def test_ensure_port_80_available_not_root(monkeypatch, capsys):
    monkeypatch.setattr(cli, "is_root", lambda: False)
    with pytest.raises(SystemExit) as exc:
        cli._ensure_port_80_available()
    assert exc.value.code == 1
    assert "Must be run as root" in capsys.readouterr().out


def test_ensure_port_80_available_quit(monkeypatch):
    monkeypatch.setattr(cli, "is_root", lambda: True)
    monkeypatch.setattr(cli, "find_process_on_port", lambda port: ["123"])
    monkeypatch.setattr(builtins, "input", lambda _: "q")

    with pytest.raises(SystemExit) as exc:
        cli._ensure_port_80_available()
    assert exc.value.code == 1


def test_ensure_port_80_available_retries(monkeypatch):
    monkeypatch.setattr(cli, "is_root", lambda: True)
    calls = iter([["123"], []])
    monkeypatch.setattr(cli, "find_process_on_port", lambda port: next(calls))
    monkeypatch.setattr(builtins, "input", lambda _: "")

    cli._ensure_port_80_available()


def test_obtain_certificate_dns_challenge(monkeypatch, capsys):
    fake_issuer = FakeAcmeCertIssuer(FakeKeyStore("/etc/ssl"), Mock(), "acme_account")

    def fake_with_keystore(key_store, solver, account_key_name="acme_account"):
        fake_issuer.key_store = key_store
        fake_issuer.solver = solver
        fake_issuer.account_key_name = account_key_name
        return fake_issuer

    monkeypatch.setattr(cli, "CloudflareChallengeSolver", lambda api_key=None: Mock(api_key=api_key))
    monkeypatch.setattr(cli, "FileSystemKeyStore", lambda path: FakeKeyStore(path))
    monkeypatch.setattr(cli.AcmeCertIssuer, "with_keystore", staticmethod(fake_with_keystore))
    monkeypatch.setattr(
        cli, "certs_from_pem", lambda *args, **kwargs: [FakeCert(datetime(2026, 1, 1, tzinfo=timezone.utc))]
    )

    cli.obtain_certificate(["example.com"], api_key="token")
    output = capsys.readouterr().out
    assert "Using Cloudflare DNS challenge." in output
    assert "Certificate expires at" in output
    assert "Key path" in output
    assert "Cert path" in output


def test_obtain_certificate_http_challenge_unknown_expiry(monkeypatch, capsys):
    fake_issuer = FakeAcmeCertIssuer(FakeKeyStore("/etc/ssl"), Mock(), "acme_account")
    server = Mock()

    monkeypatch.setattr(cli, "_ensure_port_80_available", lambda: None)
    monkeypatch.setattr(cli, "InMemoryChallengeSolver", lambda: InMemoryChallengeSolver())
    monkeypatch.setattr(cli, "_start_http_challenge_server", lambda solver, port=80: (server, Mock()))
    monkeypatch.setattr(cli, "FileSystemKeyStore", lambda path: FakeKeyStore(path))
    monkeypatch.setattr(
        cli.AcmeCertIssuer,
        "with_keystore",
        staticmethod(lambda key_store, solver, account_key_name="acme_account": fake_issuer),
    )
    monkeypatch.setattr(cli, "certs_from_pem", lambda *args, **kwargs: [])

    cli.obtain_certificate(["example.com"], api_key=None)
    output = capsys.readouterr().out
    assert "Starting HTTP challenge server" in output
    assert "Certificate expires at: unknown" in output
    server.shutdown.assert_called_once()
    server.server_close.assert_called_once()


def test_obtain_certificate_handles_error(monkeypatch, capsys):
    fake_issuer = FakeAcmeCertIssuer(FakeKeyStore("/etc/ssl"), Mock(), "acme_account")
    fake_issuer.raise_error = True
    server = Mock()

    monkeypatch.setattr(cli, "_ensure_port_80_available", lambda: None)
    monkeypatch.setattr(cli, "InMemoryChallengeSolver", lambda: InMemoryChallengeSolver())
    monkeypatch.setattr(cli, "_start_http_challenge_server", lambda solver, port=80: (server, Mock()))
    monkeypatch.setattr(cli, "FileSystemKeyStore", lambda path: FakeKeyStore(path))
    monkeypatch.setattr(
        cli.AcmeCertIssuer,
        "with_keystore",
        staticmethod(lambda key_store, solver, account_key_name="acme_account": fake_issuer),
    )

    cli.obtain_certificate(["example.com"], api_key=None)
    output = capsys.readouterr().out
    assert "An error occurred:" in output
    assert "boom" in output
    server.shutdown.assert_called_once()
    server.server_close.assert_called_once()


def test_verify_environment_dns_supported(monkeypatch, capsys):
    class FakeSolver:
        def __init__(self, api_key=None):
            self.api_key = api_key

        def supports_domain(self, domain):
            return True

    monkeypatch.setattr(cli, "CloudflareChallengeSolver", FakeSolver)
    cli.verify_environment(["example.com"], api_key="token")
    output = capsys.readouterr().out
    assert "Cloudflare account appears to manage" in output


def test_verify_environment_dns_unsupported(monkeypatch, capsys):
    class FakeSolver:
        def __init__(self, api_key=None):
            self.api_key = api_key

        def supports_domain(self, domain):
            return domain != "bad.example"

    monkeypatch.setattr(cli, "CloudflareChallengeSolver", FakeSolver)
    cli.verify_environment(["good.example", "bad.example"], api_key="token")
    output = capsys.readouterr().out
    assert "Warning: Cloudflare account does not appear to manage" in output
    assert "bad.example" in output


def test_verify_environment_http_no_domains(monkeypatch, capsys):
    monkeypatch.setattr(cli, "is_root", lambda: True)
    cli.verify_environment([], api_key=None)
    output = capsys.readouterr().out
    assert "No domains provided" in output


def test_verify_environment_http_not_root(monkeypatch, capsys):
    monkeypatch.setattr(cli, "is_root", lambda: False)

    def fail_if_called():
        raise AssertionError("should not be called")

    monkeypatch.setattr(cli, "_ensure_port_80_available", fail_if_called)
    cli.verify_environment(["example.com"], api_key=None)
    output = capsys.readouterr().out
    assert "Warning: not running as root" in output


def test_verify_environment_http_checks(monkeypatch, capsys):
    solver = InMemoryChallengeSolver()
    server = Mock()

    monkeypatch.setattr(cli, "is_root", lambda: True)
    monkeypatch.setattr(cli, "find_process_on_port", lambda port: ["999"])
    monkeypatch.setattr(cli, "_ensure_port_80_available", lambda: None)
    monkeypatch.setattr(cli, "InMemoryChallengeSolver", lambda: solver)
    monkeypatch.setattr(cli, "_start_http_challenge_server", lambda challenge_solver, port=80: (server, Mock()))

    tokens = iter(["token1", "value1", "token2", "value2", "token3", "value3"])
    monkeypatch.setattr(cli.secrets, "token_urlsafe", lambda _: next(tokens))

    def fake_get(url, allow_redirects=False, timeout=5):
        if "token1" in url:
            return Mock(status_code=200, text="value1")
        if "token2" in url:
            return Mock(status_code=500, text="oops")
        raise requests.RequestException("boom")

    monkeypatch.setattr(cli.requests, "get", fake_get)

    cli.verify_environment(["ok.example", "bad.example", "err.example"], api_key=None)
    output = capsys.readouterr().out
    assert "Warning: port 80 is in use" in output
    assert "OK: ok.example" in output
    assert "FAILED: bad.example" in output
    assert "FAILED: err.example" in output
    assert "Summary: 1 OK, 2 FAILED" in output
    assert len(solver) == 0
    server.shutdown.assert_called_once()
    server.server_close.assert_called_once()


def test_verify_environment_http_port_available(monkeypatch, capsys):
    solver = InMemoryChallengeSolver()
    server = Mock()

    monkeypatch.setattr(cli, "is_root", lambda: True)
    monkeypatch.setattr(cli, "find_process_on_port", lambda port: [])
    monkeypatch.setattr(cli, "_ensure_port_80_available", lambda: None)
    monkeypatch.setattr(cli, "InMemoryChallengeSolver", lambda: solver)
    monkeypatch.setattr(cli, "_start_http_challenge_server", lambda challenge_solver, port=80: (server, Mock()))
    monkeypatch.setattr(cli.secrets, "token_urlsafe", lambda _: "token")
    monkeypatch.setattr(cli.requests, "get", lambda *args, **kwargs: Mock(status_code=200, text="token"))

    cli.verify_environment(["ok.example"], api_key=None)
    output = capsys.readouterr().out
    assert "Port 80 is available" in output


def test_main_verify(monkeypatch):
    called = {}

    def fake_verify(domains, api_key=None):
        called["domains"] = domains
        called["api_key"] = api_key

    monkeypatch.setattr(cli, "verify_environment", fake_verify)
    monkeypatch.setattr(cli, "_resolve_cloudflare_api_key", lambda: "token")
    monkeypatch.setattr(cli.sys, "argv", ["certapi", "verify", "example.com"])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 0
    assert called["domains"] == ["example.com"]
    assert called["api_key"] == "token"


def test_main_obtain(monkeypatch):
    called = {}

    def fake_obtain(domains, api_key=None):
        called["domains"] = domains
        called["api_key"] = api_key

    monkeypatch.setattr(cli, "obtain_certificate", fake_obtain)
    monkeypatch.setattr(cli, "_resolve_cloudflare_api_key", lambda: None)
    monkeypatch.setattr(cli.sys, "argv", ["certapi", "obtain", "example.com"])

    cli.main()
    assert called["domains"] == ["example.com"]
    assert called["api_key"] is None


def test_main_help(monkeypatch):
    monkeypatch.setattr(cli.sys, "argv", ["certapi"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
