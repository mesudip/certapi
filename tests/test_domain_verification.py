from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests
from flask import Flask
from flask_restx import Api, Namespace

from certapi.challenge_solver import FilesystemChallengeSolver
from certapi.client.cert_manager_client import CertManagerClient
from certapi.errors import CertApiException
from certapi.server.api import create_api_resources


def make_api(solver):
    app = Flask(__name__)
    api = Api(app)
    namespace = Namespace("api")
    api.add_namespace(namespace)
    manager = SimpleNamespace(challenge_solvers=[solver], obtain=Mock())
    create_api_resources(namespace, manager)
    return app.test_client(), manager


def test_api_checks_payload_and_reports_every_domain_without_issuance(tmp_path, monkeypatch):
    solver = FilesystemChallengeSolver(str(tmp_path))
    api, manager = make_api(solver)
    calls = []

    def get(url, **kwargs):
        calls.append((url, kwargs))
        token = url.rsplit("/", 1)[1]
        assert (tmp_path / token).stat().st_mode & 0o777 == 0o644
        content = solver.get_challenge(token).encode() if "good.example" in url else b"wrong payload"
        return SimpleNamespace(status_code=200, content=content)

    monkeypatch.setattr(requests, "get", get)
    response = api.get(
        "/api/verify", query_string=[("hostname", d) for d in ["good.example", "bad.example", "*.example"]]
    )
    assert response.status_code == 200
    assert response.json == {"verified": ["good.example"], "failed": ["bad.example", "*.example"]}
    assert len(calls) == 2
    assert all(options == {"allow_redirects": False, "timeout": 3} for _, options in calls)
    assert list(tmp_path.iterdir()) == []
    manager.obtain.assert_not_called()


def test_api_requires_hostname_and_http_solver():
    api, manager = make_api(Mock())
    assert api.get("/api/verify").status_code == 400
    assert api.get("/api/verify?hostname=example.com").status_code == 503
    manager.obtain.assert_not_called()


@pytest.mark.parametrize("status,payload", [(301, b""), (404, b""), (200, b"\xff"), (200, b"wrong")])
def test_verification_rejects_redirect_missing_or_mismatched_payload(tmp_path, monkeypatch, status, payload):
    solver = FilesystemChallengeSolver(str(tmp_path))
    monkeypatch.setattr(requests, "get", lambda *a, **k: SimpleNamespace(status_code=status, content=payload))
    assert solver.verify_domain("example.com") is False
    assert list(tmp_path.iterdir()) == []


def test_timeout_does_not_stop_other_domains_and_cleans_up(tmp_path, monkeypatch):
    solver = FilesystemChallengeSolver(str(tmp_path))

    def get(url, **kwargs):
        if "bad.example" in url:
            raise requests.Timeout("timed out")
        return SimpleNamespace(status_code=200, content=Path(tmp_path / url.rsplit("/", 1)[1]).read_bytes())

    monkeypatch.setattr(requests, "get", get)
    assert solver.verify_domain(["bad.example", "good.example"]) == ["good.example"]
    assert list(tmp_path.iterdir()) == []


def test_unexpected_failure_cleans_up_probe(tmp_path, monkeypatch):
    solver = FilesystemChallengeSolver(str(tmp_path))
    monkeypatch.setattr(requests, "get", Mock(side_effect=RuntimeError("unexpected")))
    with pytest.raises(RuntimeError):
        solver.verify_domain("example.com")
    assert list(tmp_path.iterdir()) == []


def test_client_checks_domains_via_api(monkeypatch, tmp_path):
    solver = FilesystemChallengeSolver(str(tmp_path))
    api, manager = make_api(solver)
    monkeypatch.setattr(
        requests,
        "get",
        lambda url, **kw: SimpleNamespace(status_code=200, content=Path(tmp_path / url.rsplit("/", 1)[1]).read_bytes()),
    )

    def request(method, url, params=None, **kwargs):
        result = api.get("/api/verify", query_string=params)
        response = requests.Response()
        response.status_code = result.status_code
        response.url = url
        response._content = result.data
        return response

    monkeypatch.setattr(requests, "request", request)
    assert CertManagerClient("http://certapi:8080/").verify_domains("example.com") == ["example.com"]
    manager.obtain.assert_not_called()


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"verified": ["example.com"]},
        {"verified": ["other.com"], "failed": []},
        {"verified": ["example.com"], "failed": ["example.com"]},
        {"verified": [1], "failed": []},
        "OK",
    ],
)
def test_client_rejects_malformed_verification_responses(monkeypatch, data):
    client = CertManagerClient("http://certapi:8080")
    monkeypatch.setattr(client, "_get", lambda *a, **k: data)
    with pytest.raises(CertApiException, match="Invalid CertAPI"):
        client.verify_domains("example.com")


def test_old_server_fails_with_upgrade_message(monkeypatch):
    response = requests.Response()
    response.status_code = 404
    response.url = "http://certapi:8080/api/verify"
    response._content = b"Not Found"
    monkeypatch.setattr(requests, "request", lambda *a, **k: response)
    with pytest.raises(CertApiException, match="upgrade the server"):
        CertManagerClient("http://certapi:8080").verify_domains("example.com")
