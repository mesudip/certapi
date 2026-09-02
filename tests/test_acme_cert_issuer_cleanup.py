import importlib
from unittest.mock import Mock

import pytest

from certapi.issuers.AcmeCertIssuer import AcmeCertIssuer


acme_cert_issuer_module = importlib.import_module("certapi.issuers.AcmeCertIssuer")


class FailingChallenge:
    def __init__(self, domain, fail_verify=False):
        self.domain = domain
        self.fail_verify = fail_verify

    def as_key_value(self, type=None):
        return f"_acme-challenge.{self.domain}", f"value-{self.domain}"

    def verify(self, type=None):
        if self.fail_verify:
            raise RuntimeError("challenge verification failed")
        return True


class RecordingSolver:
    def __init__(self, failing_delete_key=None):
        self.failing_delete_key = failing_delete_key
        self.saved = []
        self.deleted = []

    def supported_challenge_type(self):
        return "dns-01"

    def save_challenge(self, key, value, domain):
        self.saved.append((key, value, domain))

    def delete_challenge(self, key, domain):
        self.deleted.append((key, domain))
        if key == self.failing_delete_key:
            raise RuntimeError("provider cleanup failed")


def test_sign_csr_cleans_every_saved_challenge_without_masking_original_error(monkeypatch):
    first = FailingChallenge("first.example.com")
    second = FailingChallenge("second.example.com", fail_verify=True)
    order = Mock()
    order.remaining_challenges.return_value = [first, second]
    acme = Mock()
    acme.create_order.return_value = order
    solver = RecordingSolver(failing_delete_key="_acme-challenge.second.example.com")

    issuer = object.__new__(AcmeCertIssuer)
    issuer.acme = acme
    issuer.challenge_solver = solver
    issuer.self_verify_challenge = False
    issuer.get_csr_hostnames = lambda _csr: ["first.example.com", "second.example.com"]
    monkeypatch.setattr(acme_cert_issuer_module.time, "sleep", lambda _seconds: None)

    with pytest.raises(RuntimeError, match="challenge verification failed"):
        issuer.sign_csr(Mock())

    assert [saved[0] for saved in solver.saved] == [
        "_acme-challenge.first.example.com",
        "_acme-challenge.second.example.com",
    ]
    assert solver.deleted == [
        ("_acme-challenge.second.example.com", "second.example.com"),
        ("_acme-challenge.first.example.com", "first.example.com"),
    ]
