from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509

from certapi.acme import AcmeError
from certapi.errors import DomainNotOwnedException
from certapi.domain_batching import create_safe_domain_batches, would_trigger
from certapi import Key
from certapi.manager.acme_cert_manager import AcmeCertManager


class DummyKeyStore:
    def __init__(self):
        self.saved_keys = []
        self.saved_certs = []

    def find_key_and_cert_by_domain(self, _domain):
        return None

    def save_key(self, key, name):
        self.saved_keys.append((key, name))
        return f"key-{len(self.saved_keys)}"

    def save_cert(self, key_id, cert, domains):
        self.saved_certs.append((key_id, cert, tuple(domains)))


class DummySolver:
    def supports_domain(self, _domain):
        return True

    def supports_domain_strict(self, _domain):
        return True


class RecordingStrictSolver(DummySolver):
    def __init__(self):
        self.checked_domains = []

    def supports_domain_strict(self, domain):
        self.checked_domains.append(domain)
        return domain == "api.example.com"


class DummyIssuer:
    def __init__(self):
        self.calls = []

    def generate_key_and_cert_for_domains(self, domains, **_kwargs):
        self.calls.append(list(domains))
        return "dummy-key", "dummy-cert"


class FailingWildcardIssuer(DummyIssuer):
    def generate_key_and_cert_for_domains(self, domains, **_kwargs):
        self.calls.append(list(domains))
        if domains[0].startswith("*."):
            raise AcmeError("wildcard issuance failed", {}, "test issuance")
        return "dummy-key", "dummy-cert"


class UnexpectedFailingIssuer(DummyIssuer):
    def generate_key_and_cert_for_domains(self, domains, **_kwargs):
        self.calls.append(list(domains))
        raise RuntimeError("unexpected issuer failure")


def test_would_trigger_exact_rule():
    blocked = {"abc", "def", "ghi"}
    assert would_trigger(["x", "abc", "def", "ghi", "example", "com"], blocked) is True
    assert would_trigger(["x", "abc", "def", "example", "com"], blocked) is False
    assert would_trigger(["x", "abc", "abc", "example", "com"], blocked) is True


def test_create_safe_domain_batches_compacts_non_triggering_domains():
    domains = ["x.example.com", "y.example.com", "y.example.com"]
    assert create_safe_domain_batches(domains) == [["x.example.com", "y.example.com"]]


def test_create_safe_domain_batches_preserves_wildcard_domains():
    domains = ["*.example.com", "api.example.com"]
    assert create_safe_domain_batches(domains) == [["*.example.com"], ["api.example.com"]]


def test_issue_certificate_default_does_not_batch():
    key_store = DummyKeyStore()
    issuer = DummyIssuer()
    solver = DummySolver()
    manager = AcmeCertManager(key_store=key_store, cert_issuer=issuer, challenge_solvers=[solver])

    domains = [
        "xyz.com",
        "abcd.xyz.com",
        "def.abcd.xyz.com",
    ]
    manager.issue_certificate(hosts=domains)

    assert issuer.calls == [domains]


def test_issue_certificate_in_batches_uses_custom_batch_generator():
    key_store = DummyKeyStore()
    issuer = DummyIssuer()
    solver = DummySolver()
    manager = AcmeCertManager(key_store=key_store, cert_issuer=issuer, challenge_solvers=[solver])

    domains = [
        "x.abc.def.ghi.example.com",
        "root.example.com",
    ]
    response = manager.issue_certificate_in_batches(
        hosts=domains,
        batch_generator=lambda d: create_safe_domain_batches(
            d,
            blocked_labels=["abc", "def", "ghi"],
        ),
    )

    assert issuer.calls == [
        ["root.example.com"],
        ["x.abc.def.ghi.example.com"],
    ]
    assert len(response.issued) == 2
    assert [issued.domains for issued in response.issued] == issuer.calls


def test_issue_certificate_in_batches_does_not_call_custom_generator_with_empty_domains():
    key_store = DummyKeyStore()
    issuer = DummyIssuer()
    solver = DummySolver()
    manager = AcmeCertManager(key_store=key_store, cert_issuer=issuer, challenge_solvers=[solver])

    def nonempty_batch_generator(domains):
        assert domains
        return [domains]

    response = manager.issue_certificate_in_batches(
        hosts=["*.example.com"],
        batch_generator=nonempty_batch_generator,
    )

    assert issuer.calls == [["*.example.com"]]
    assert [issued.domains for issued in response.issued] == [["*.example.com"]]


def test_obtain_batch_domains_uses_safe_batches():
    key_store = DummyKeyStore()
    issuer = DummyIssuer()
    solver = DummySolver()
    manager = AcmeCertManager(key_store=key_store, cert_issuer=issuer, challenge_solvers=[solver])

    domains = [
        "x.abc.def.ghi.example.com",
        "root.example.com",
    ]
    response = manager.obtain(hosts=domains, batch_domains=True)

    assert issuer.calls == [
        ["root.example.com"],
        ["x.abc.def.ghi.example.com"],
    ]
    assert len(response.issued) == 2


def test_obtain_batch_domains_preserves_wildcard_domains():
    key_store = DummyKeyStore()
    issuer = DummyIssuer()
    solver = DummySolver()
    manager = AcmeCertManager(key_store=key_store, cert_issuer=issuer, challenge_solvers=[solver])

    domains = ["*.example.com", "api.example.com"]
    response = manager.obtain(hosts=domains, batch_domains=True)

    assert issuer.calls == [["*.example.com"]]
    assert response.issued[0].domains == ["*.example.com"]


def test_obtain_batch_domains_normalizes_wildcard_before_issuance():
    key_store = DummyKeyStore()
    issuer = DummyIssuer()
    solver = DummySolver()
    manager = AcmeCertManager(key_store=key_store, cert_issuer=issuer, challenge_solvers=[solver])

    response = manager.obtain(hosts=["  *.Example.COM.  "], batch_domains=True)

    assert issuer.calls == [["*.example.com"]]
    assert response.issued[0].domains == ["*.example.com"]


def test_obtain_batch_domains_falls_back_to_concrete_after_wildcard_failure():
    key_store = DummyKeyStore()
    issuer = FailingWildcardIssuer()
    solver = DummySolver()
    manager = AcmeCertManager(key_store=key_store, cert_issuer=issuer, challenge_solvers=[solver])

    response = manager.obtain(hosts=["*.example.com", "api.example.com"], batch_domains=True, skip_failing=True)

    assert issuer.calls == [["*.example.com"], ["api.example.com"]]
    assert [cert.domains for cert in response.issued] == [["api.example.com"]]


def test_obtain_batch_domains_propagates_wildcard_failure_when_not_skipping():
    key_store = DummyKeyStore()
    issuer = FailingWildcardIssuer()
    solver = DummySolver()
    manager = AcmeCertManager(key_store=key_store, cert_issuer=issuer, challenge_solvers=[solver])

    with pytest.raises(AcmeError, match="wildcard issuance failed"):
        manager.obtain(hosts=["*.example.com", "api.example.com"], batch_domains=True, skip_failing=False)

    assert issuer.calls == [["*.example.com"]]


def test_obtain_batch_domains_does_not_hide_unexpected_issuer_failure():
    key_store = DummyKeyStore()
    issuer = UnexpectedFailingIssuer()
    solver = DummySolver()
    manager = AcmeCertManager(key_store=key_store, cert_issuer=issuer, challenge_solvers=[solver])

    with pytest.raises(RuntimeError, match="unexpected issuer failure"):
        manager.obtain(hosts=["*.example.com"], batch_domains=True, skip_failing=True)


def test_obtain_batch_domains_issues_all_wildcards_before_uncovered_concrete_domains():
    key_store = DummyKeyStore()
    issuer = DummyIssuer()
    solver = DummySolver()
    manager = AcmeCertManager(key_store=key_store, cert_issuer=issuer, challenge_solvers=[solver])

    response = manager.obtain(
        hosts=[
            "*.example.com",
            "api.example.com",
            "api.deep.example.com",
            "*.deep.example.com",
            "service.deep.example.com",
            "unrelated.test.com",
        ],
        batch_domains=True,
    )

    assert issuer.calls == [
        ["*.example.com"],
        ["*.deep.example.com"],
        ["unrelated.test.com"],
    ]
    assert [cert.domains for cert in response.issued] == issuer.calls


def test_obtain_batch_domains_parent_wildcard_does_not_cover_nested_concrete_domain():
    key_store = DummyKeyStore()
    issuer = DummyIssuer()
    solver = DummySolver()
    manager = AcmeCertManager(key_store=key_store, cert_issuer=issuer, challenge_solvers=[solver])

    manager.obtain(hosts=["*.example.com", "api.deep.example.com"], batch_domains=True)

    assert issuer.calls == [["*.example.com"], ["api.deep.example.com"]]


def test_obtain_without_batching_preserves_explicit_combined_san_request():
    key_store = DummyKeyStore()
    issuer = DummyIssuer()
    solver = DummySolver()
    manager = AcmeCertManager(key_store=key_store, cert_issuer=issuer, challenge_solvers=[solver])

    response = manager.obtain(hosts=["*.example.com", "api.example.com"], batch_domains=False)

    assert issuer.calls == [["*.example.com", "api.example.com"]]
    assert response.issued[0].domains == ["*.example.com", "api.example.com"]


def test_obtain_existing_wildcard_response_preserves_wildcard_domain():
    now = datetime.now(UTC)
    key = Key.generate("ecdsa")
    csr = key.create_csr(domain="*.example.com", alt_names=["*.example.com"])
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "pytest.certapi.local")]))
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=90))
    )
    for ext in csr.extensions:
        cert_builder = cert_builder.add_extension(ext.value, ext.critical)
    cert = key.sign_csr(cert_builder)

    class WildcardKeyStore(DummyKeyStore):
        def find_key_and_cert_covering_domain(self, domain):
            if domain == "api.example.com":
                return ("*.example.com", "wildcard-id", key, [cert])
            return None

    issuer = DummyIssuer()
    solver = DummySolver()
    manager = AcmeCertManager(key_store=WildcardKeyStore(), cert_issuer=issuer, challenge_solvers=[solver])

    response = manager.obtain(hosts=["api.example.com"])

    assert issuer.calls == []
    assert [cert.domains for cert in response.existing] == [["*.example.com"]]
    assert response.issued == []


def test_issue_certificate_self_verify_false_skips_strict_solver_check():
    class StrictFailingSolver(DummySolver):
        def supports_domain_strict(self, _domain):
            return False

    key_store = DummyKeyStore()
    issuer = DummyIssuer()
    solver = StrictFailingSolver()
    manager = AcmeCertManager(key_store=key_store, cert_issuer=issuer, challenge_solvers=[solver])

    manager.issue_certificate(hosts=["force.example.com"], self_verify=False)

    assert issuer.calls == [["force.example.com"]]


def test_issue_certificate_self_verify_true_uses_strict_solver_check():
    class StrictFailingSolver(DummySolver):
        def supports_domain_strict(self, _domain):
            return False

    key_store = DummyKeyStore()
    issuer = DummyIssuer()
    solver = StrictFailingSolver()
    manager = AcmeCertManager(key_store=key_store, cert_issuer=issuer, challenge_solvers=[solver])

    response = manager.issue_certificate(hosts=["force.example.com"])

    assert issuer.calls == []
    assert response.issued == []


def test_obtain_self_verify_true_raises_when_all_domains_fail_and_skip_failing_false():
    class StrictFailingSolver(DummySolver):
        def supports_domain_strict(self, _domain):
            return False

    key_store = DummyKeyStore()
    issuer = DummyIssuer()
    solver = StrictFailingSolver()
    manager = AcmeCertManager(key_store=key_store, cert_issuer=issuer, challenge_solvers=[solver])

    try:
        manager.obtain(hosts=["force.example.com"], skip_failing=False)
    except ValueError as e:
        assert "None of the domains are owned" in str(e)
    else:
        raise AssertionError("expected strict obtain failure")

    assert issuer.calls == []


class SolverFailingWildcardIssuer(DummyIssuer):
    """Mimics a DNS solver failure, which raises CertApiException rather than AcmeError."""

    def generate_key_and_cert_for_domains(self, domains, **_kwargs):
        self.calls.append(list(domains))
        if domains[0].startswith("*."):
            raise DomainNotOwnedException("zone not owned", {}, "Cloudflare Create Record")
        return "dummy-key", "dummy-cert"


def test_obtain_batch_domains_falls_back_after_non_acme_solver_failure():
    key_store = DummyKeyStore()
    issuer = SolverFailingWildcardIssuer()
    solver = DummySolver()
    manager = AcmeCertManager(key_store=key_store, cert_issuer=issuer, challenge_solvers=[solver])

    response = manager.obtain(
        hosts=["*.example.com", "api.example.com", "other.com"],
        batch_domains=True,
        skip_failing=True,
    )

    assert issuer.calls == [["*.example.com"], ["api.example.com", "other.com"]]
    assert [cert.domains for cert in response.issued] == [["api.example.com", "other.com"]]


def test_obtain_batch_domains_propagates_solver_failure_when_not_skipping():
    key_store = DummyKeyStore()
    issuer = SolverFailingWildcardIssuer()
    solver = DummySolver()
    manager = AcmeCertManager(key_store=key_store, cert_issuer=issuer, challenge_solvers=[solver])

    with pytest.raises(DomainNotOwnedException):
        manager.obtain(hosts=["*.example.com", "api.example.com"], batch_domains=True, skip_failing=False)


def test_obtain_normalizes_and_dedupes_concrete_domains_before_issuance():
    key_store = DummyKeyStore()
    issuer = DummyIssuer()
    solver = DummySolver()
    manager = AcmeCertManager(key_store=key_store, cert_issuer=issuer, challenge_solvers=[solver])

    response = manager.obtain(hosts=["  API.Example.COM.  ", "api.example.com"], batch_domains=False)

    assert issuer.calls == [["api.example.com"]]
    assert key_store.saved_keys[0][1] == "api.example.com"
    assert key_store.saved_certs[0][2] == ("api.example.com",)
    assert response.issued[0].domains == ["api.example.com"]


def test_obtain_normalizes_before_strict_solver_selection():
    key_store = DummyKeyStore()
    issuer = DummyIssuer()
    solver = RecordingStrictSolver()
    manager = AcmeCertManager(key_store=key_store, cert_issuer=issuer, challenge_solvers=[solver])

    manager.obtain(hosts=["  API.Example.COM.  "])

    assert solver.checked_domains == ["api.example.com"]
    assert issuer.calls == [["api.example.com"]]


class ScopedSolver(DummySolver):
    """Solver that only claims a fixed set of domains, so batches split per solver."""

    def __init__(self, domains):
        self.domains = set(domains)

    def supports_domain(self, domain):
        return domain in self.domains

    def supports_domain_strict(self, domain):
        return domain in self.domains


class SelectiveFailingIssuer(DummyIssuer):
    def __init__(self, failing_domain):
        super().__init__()
        self.failing_domain = failing_domain

    def generate_key_and_cert_for_domains(self, domains, **_kwargs):
        self.calls.append(list(domains))
        if self.failing_domain in domains:
            raise DomainNotOwnedException("zone not owned", {}, "Cloudflare Create Record")
        return "dummy-key", "dummy-cert"


def test_skip_failing_applies_without_batching_across_solvers():
    """Two solvers means two batches even when batch_domains is False."""
    issuer = SelectiveFailingIssuer("a.com")
    manager = AcmeCertManager(
        key_store=DummyKeyStore(),
        cert_issuer=issuer,
        challenge_solvers=[ScopedSolver(["a.com"]), ScopedSolver(["b.com"])],
    )

    response = manager.obtain(hosts=["a.com", "b.com"], batch_domains=False, skip_failing=True)

    assert issuer.calls == [["a.com"], ["b.com"]]
    assert [cert.domains for cert in response.issued] == [["b.com"]]
    assert [failure.domains for failure in response.failed] == [["a.com"]]
    assert response.failed[0].name == "DomainNotOwnedException"
    assert response.failed[0].step == "Cloudflare Create Record"


def test_skip_failing_false_fails_fast_without_attempting_later_batches():
    issuer = SelectiveFailingIssuer("a.com")
    manager = AcmeCertManager(
        key_store=DummyKeyStore(),
        cert_issuer=issuer,
        challenge_solvers=[ScopedSolver(["a.com"]), ScopedSolver(["b.com"])],
    )

    with pytest.raises(DomainNotOwnedException):
        manager.obtain(hosts=["a.com", "b.com"], batch_domains=False, skip_failing=False)

    assert issuer.calls == [["a.com"]]


def test_total_failure_still_raises_even_when_skipping():
    """A single-domain call that fails keeps raising rather than returning an empty response."""
    issuer = SelectiveFailingIssuer("a.com")
    manager = AcmeCertManager(
        key_store=DummyKeyStore(), cert_issuer=issuer, challenge_solvers=[ScopedSolver(["a.com"])]
    )

    with pytest.raises(DomainNotOwnedException):
        manager.obtain(hosts=["a.com"], batch_domains=True, skip_failing=True)


def test_failed_batches_survive_json_round_trip():
    from certapi.http.types import CertificateResponse

    issuer = SelectiveFailingIssuer("a.com")
    manager = AcmeCertManager(
        key_store=DummyKeyStore(),
        cert_issuer=issuer,
        challenge_solvers=[ScopedSolver(["a.com"]), ScopedSolver(["b.com"])],
    )
    response = manager.obtain(hosts=["a.com", "b.com"], skip_failing=True)

    restored = CertificateResponse.from_json(response.to_json())

    assert [f.domains for f in restored.failed] == [["a.com"]]
    assert restored.failed[0].message == "zone not owned"
    # `detail` never crosses the wire.
    assert "detail" not in response.to_json()["failed"][0]


def test_old_client_payload_without_failed_key_still_parses():
    from certapi.http.types import CertificateResponse

    restored = CertificateResponse.from_json({"existing": [], "issued": []})

    assert restored.failed == []


def test_empty_failed_list_is_omitted_from_json():
    from certapi.http.types import CertificateResponse

    assert CertificateResponse().to_json() == {"existing": [], "issued": []}
