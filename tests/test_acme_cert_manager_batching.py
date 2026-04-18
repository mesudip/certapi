from certapi.domain_batching import create_safe_domain_batches, split_domain_to_safe_groups, would_trigger
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


def test_split_domain_to_safe_groups_greedy():
    groups = split_domain_to_safe_groups(
        "x.abc.def.ghi.example.com",
        blocked_labels=["abc", "def", "ghi"],
    )
    assert groups == [["x", "abc", "def"], ["ghi", "example", "com"]]


def test_create_safe_domain_batches_compacts_non_triggering_domains():
    domains = ["x.example.com", "y.example.com", "y.example.com"]
    assert create_safe_domain_batches(domains) == [["x.example.com", "y.example.com"]]


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
        ["x.abc.def"],
        ["ghi.example.com"],
    ]
    assert len(response.issued) == 3
    assert [issued.domains for issued in response.issued] == issuer.calls
