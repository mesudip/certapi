from unittest.mock import Mock

from certapi.client.cert_manager_client import CertManagerClient
from certapi.http.types import CertificateResponse
from certapi.manager.acme_cert_manager import AcmeCertManager


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
    )

    assert res is expected
    assert captured["hosts"] == ["example.com"]
    assert captured["key_type"] == "ecdsa"
    assert captured["expiry_days"] == 90
    assert captured["renew_threshold_days"] == 30
    assert captured["batch_generator"] is None


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
    )

    assert isinstance(res, CertificateResponse)
    assert captured["path"] == "/api/obtain"
    assert captured["params"]["hostname"] == ["example.com"]
    assert captured["params"]["key_type"] == "ecdsa"
    assert captured["params"]["renew_threshold_days"] == 12
    assert captured["params"]["skip_failing"] is False
    assert captured["params"]["batch_domains"] is True
