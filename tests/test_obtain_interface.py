from unittest.mock import Mock

from flask import Flask
from flask_restx import Api, Namespace

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
