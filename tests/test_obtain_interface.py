from unittest.mock import Mock

import pytest
import requests
from flask import Flask
from flask_restx import Api, Namespace

from certapi.errors import CertApiException, HttpError, NetworkError
from certapi.client.cert_manager_client import CertManagerClient
from certapi.domain_batching import create_safe_domain_batches
from certapi.http.types import CertificateResponse
from certapi.manager.acme_cert_manager import AcmeCertManager
from certapi.server.api import create_api_resources


def test_acme_cert_manager_issue_certificate_delegates_to_obtain(monkeypatch):
    manager = AcmeCertManager(key_store=Mock(), cert_issuer=Mock(), challenge_solvers=[])
    expected = CertificateResponse()
    captured = {}

    def fake_obtain(**kwargs):
        captured.update(kwargs)
        return expected

    monkeypatch.setattr(manager, "obtain", fake_obtain)
    res = manager.issue_certificate(
        hosts=["example.com"],
        key_type="rsa",
        expiry_days=91,
        country="NP",
        state="Bagmati",
        locality="Kathmandu",
        organization="Org",
        user_id="u1",
        renew_threshold_days=25,
        skip_failing=False,
        batch_domains=True,
        self_verify=False,
    )

    assert res is expected
    assert captured["hosts"] == ["example.com"]
    assert captured["key_type"] == "rsa"
    assert captured["expiry_days"] == 91
    assert captured["country"] == "NP"
    assert captured["state"] == "Bagmati"
    assert captured["locality"] == "Kathmandu"
    assert captured["organization"] == "Org"
    assert captured["user_id"] == "u1"
    assert captured["renew_threshold_days"] == 25
    assert captured["skip_failing"] is False
    assert captured["batch_domains"] is True
    assert captured["self_verify"] is False


def test_acme_cert_manager_obtain_uses_internal_issue_path(monkeypatch):
    manager = AcmeCertManager(key_store=Mock(), cert_issuer=Mock(), challenge_solvers=[])
    expected = CertificateResponse()
    captured = {}

    def fake_internal(**kwargs):
        captured.update(kwargs)
        return expected

    monkeypatch.setattr(manager, "_issue_certificate_internal", fake_internal)
    res = manager.obtain(
        hosts=["example.com"],
        key_type="ecdsa",
        expiry_days=90,
        renew_threshold_days=30,
        skip_failing=False,
        batch_domains=True,
        self_verify=False,
    )

    assert res is expected
    assert captured["hosts"] == ["example.com"]
    assert captured["key_type"] == "ecdsa"
    assert captured["expiry_days"] == 90
    assert captured["renew_threshold_days"] == 30
    assert captured["batch_generator"] is create_safe_domain_batches
    assert captured["skip_failing"] is False
    assert captured["self_verify"] is False


def test_cert_manager_client_issue_certificate_delegates_to_obtain(monkeypatch):
    client = CertManagerClient("https://certapi.local")
    expected = CertificateResponse()
    captured = {}

    def fake_obtain(**kwargs):
        captured.update(kwargs)
        return expected

    monkeypatch.setattr(client, "obtain", fake_obtain)
    res = client.issue_certificate(
        hosts=["example.com"],
        key_type="rsa",
        expiry_days=89,
        country="NP",
        state="Bagmati",
        locality="Kathmandu",
        organization="Org",
        user_id="u1",
        renew_threshold_days=15,
        skip_failing=False,
        batch_domains=True,
        self_verify=False,
    )

    assert res is expected
    assert captured["hosts"] == ["example.com"]
    assert captured["key_type"] == "rsa"
    assert captured["expiry_days"] == 89
    assert captured["country"] == "NP"
    assert captured["state"] == "Bagmati"
    assert captured["locality"] == "Kathmandu"
    assert captured["organization"] == "Org"
    assert captured["user_id"] == "u1"
    assert captured["renew_threshold_days"] == 15
    assert captured["skip_failing"] is False
    assert captured["batch_domains"] is True
    assert captured["self_verify"] is False


def test_cert_manager_client_obtain_calls_api_obtain(monkeypatch):
    client = CertManagerClient("https://certapi.local")
    captured = {}

    def fake_get(path, params=None):
        captured["path"] = path
        captured["params"] = params
        return {"existing": [], "issued": []}

    monkeypatch.setattr(client, "_get", fake_get)
    res = client.obtain(
        hosts=["example.com"],
        key_type="ecdsa",
        renew_threshold_days=12,
        skip_failing=False,
        batch_domains=True,
        self_verify=False,
    )

    assert isinstance(res, CertificateResponse)
    assert captured["path"] == "/api/obtain"
    assert captured["params"]["hostname"] == ["example.com"]
    assert captured["params"]["key_type"] == "ecdsa"
    assert captured["params"]["renew_threshold_days"] == 12
    assert captured["params"]["skip_failing"] is False
    assert captured["params"]["batch_domains"] is True
    assert captured["params"]["self_verify"] is False


def test_cert_manager_client_setup_uses_health_endpoint(monkeypatch):
    client = CertManagerClient("https://certapi.local")
    captured = {}

    def fake_get(path, params=None, timeout=None):
        captured["path"] = path
        captured["params"] = params
        captured["timeout"] = timeout
        return {"status": "ok"}

    monkeypatch.setattr(client, "_get", fake_get)

    client.setup()

    assert captured["path"] == "/api/health"
    assert captured["params"] is None
    assert captured["timeout"] is None


def test_cert_manager_client_wait_healthy_returns_true_when_health_check_succeeds(monkeypatch):
    client = CertManagerClient("https://certapi.local")

    monkeypatch.setattr(client, "setup", lambda timeout=None: {"status": "ok"})

    assert client.wait_healthy() is True


def test_cert_manager_client_wait_healthy_returns_false_when_raise_exception_disabled(monkeypatch):
    client = CertManagerClient("https://certapi.local")

    def fail_setup(timeout=None):
        raise CertApiException("invalid health response")

    monkeypatch.setattr(client, "setup", fail_setup)

    assert client.wait_healthy(timeout_seconds=0, raise_exception=False) is False


def test_cert_manager_client_wait_healthy_raises_by_default(monkeypatch):
    client = CertManagerClient("https://certapi.local")

    def fail_setup(timeout=None):
        raise NetworkError(None, "connection refused")

    monkeypatch.setattr(client, "setup", fail_setup)

    with pytest.raises(NetworkError):
        client.wait_healthy(timeout_seconds=0)


def test_cert_manager_client_setup_raises_http_error_with_response_body(monkeypatch):
    client = CertManagerClient("https://certapi.local")
    response = requests.Response()
    response.status_code = 503
    response.url = "https://certapi.local/api/health"
    response._content = b'{"message": "service unavailable"}'
    response.request = requests.Request("GET", response.url).prepare()

    def fake_request(*_args, **_kwargs):
        return response

    monkeypatch.setattr(requests, "request", fake_request)

    with pytest.raises(HttpError) as exc_info:
        client.setup()

    assert "HTTP 503" in exc_info.value.message
    assert exc_info.value.detail["body"]["message"] == "service unavailable"


def test_cert_manager_client_setup_raises_network_error_for_unreachable_server(monkeypatch):
    client = CertManagerClient("https://certapi.local")

    def fake_request(*_args, **_kwargs):
        raise requests.exceptions.ConnectionError("connection refused")

    monkeypatch.setattr(requests, "request", fake_request)

    with pytest.raises(NetworkError) as exc_info:
        client.setup()

    assert "unreachable" in exc_info.value.message
    assert exc_info.value.detail["message"] == "connection refused"


def test_cert_manager_client_get_rejects_successful_non_json_response(monkeypatch):
    client = CertManagerClient("https://certapi.local")
    response = requests.Response()
    response.status_code = 200
    response.url = "https://certapi.local/api/health"
    response._content = b"ok"
    response.request = requests.Request("GET", response.url).prepare()

    def fake_request(*_args, **_kwargs):
        return response

    monkeypatch.setattr(requests, "request", fake_request)

    with pytest.raises(CertApiException) as exc_info:
        client.setup()

    assert "not valid JSON" in exc_info.value.message
    assert exc_info.value.detail["body"] == "ok"


def test_api_health_endpoint():
    app = Flask(__name__)
    api = Api(app)
    api_ns = Namespace("api")
    api.add_namespace(api_ns)

    create_api_resources(api_ns, Mock())

    response = app.test_client().get("/api/health")

    assert response.status_code == 200
    assert response.json == {"status": "ok"}


def test_remote_obtain_self_verify_false_skips_server_prefilter():
    app = Flask(__name__)
    api = Api(app)
    api_ns = Namespace("api")
    api.add_namespace(api_ns)

    class Solver:
        def supports_domain_strict(self, _domain):
            return False

    class Manager:
        challenge_solvers = [Solver()]

        def __init__(self):
            self.calls = []

        def obtain(self, hosts, **kwargs):
            self.calls.append({"hosts": hosts, "kwargs": kwargs})
            return CertificateResponse()

    manager = Manager()
    create_api_resources(api_ns, manager)

    response = app.test_client().get("/api/obtain?hostname=force.example.com&self_verify=false")

    assert response.status_code == 200
    assert manager.calls[0]["hosts"] == ["force.example.com"]
    assert manager.calls[0]["kwargs"]["self_verify"] is False


def test_remote_obtain_self_verify_true_delegates_strict_failure_to_manager():
    app = Flask(__name__)
    api = Api(app)
    api_ns = Namespace("api")
    api.add_namespace(api_ns)

    class Solver:
        def supports_domain_strict(self, _domain):
            return False

    class Manager:
        challenge_solvers = [Solver()]

        def obtain(self, hosts, **kwargs):
            assert hosts == ["force.example.com"]
            assert kwargs["self_verify"] is True
            raise ValueError("None of the domains are owned by this machine or could be verified")

    create_api_resources(api_ns, Manager())

    response = app.test_client().get("/api/obtain?hostname=force.example.com")

    assert response.status_code == 400
