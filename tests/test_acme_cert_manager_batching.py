from datetime import UTC, datetime, timedelta

from cryptography import x509

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


class DummyIssuer:
    def __init__(self):
        self.calls = []

    def generate_key_and_cert_for_domains(self, domains, **_kwargs):
        self.calls.append(list(domains))
        return "dummy-key", "dummy-cert"


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
    assert create_safe_domain_batches(domains) == [["*.example.com", "api.example.com"]]


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
