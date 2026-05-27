import threading
import time
from datetime import UTC, datetime, timedelta
from tempfile import TemporaryDirectory

import pytest
from cryptography import x509

from certapi.client import RenewalManager
from certapi.client.cert_manager_client import CertManagerClient
from certapi.crypto.crypto import cert_to_pem
from certapi.errors import NetworkError
from certapi.http.types import CertificateResponse, IssuedCert
from certapi.keystore.SqliteKeyStore import SqliteKeyStore
from certapi.manager.acme_cert_manager import DEFAULT_RENEW_THRESHOLD_DAYS
from certapi import Key


class DummyClient:
    def __init__(self):
        self.calls = []
        self._handlers = {}

    def set_handler(self, domain, handler):
        self._handlers[domain] = handler

    def obtain(self, hosts, **kwargs):
        host = hosts[0] if isinstance(hosts, list) else hosts
        self.calls.append({"host": host, "hosts": hosts, "kwargs": kwargs})
        handler = self._handlers.get(host)
        if handler is None:
            return CertificateResponse()
        if isinstance(handler, Exception):
            raise handler
        if callable(handler):
            return handler(host, kwargs)
        return handler

    def issue_certificate(self, hosts, **kwargs):
        return self.obtain(hosts, **kwargs)


class DummyClientWithObtain(DummyClient):
    def __init__(self):
        super().__init__()
        self.obtain_calls = []
        self.issue_calls = []

    def obtain(self, hosts, **kwargs):
        host = hosts[0] if isinstance(hosts, list) else hosts
        self.obtain_calls.append({"host": host, "hosts": hosts, "kwargs": kwargs})
        return super().obtain(hosts, **kwargs)

    def issue_certificate(self, hosts, **kwargs):
        host = hosts[0] if isinstance(hosts, list) else hosts
        self.issue_calls.append({"host": host, "hosts": hosts, "kwargs": kwargs})
        return super().obtain(hosts, **kwargs)


class DummyRemoteClient(CertManagerClient):
    def __init__(self, response=None, error=None, started=None, release=None):
        super().__init__("https://certapi.example.test")
        self.response = response or CertificateResponse()
        self.error = error
        self.started = started
        self.release = release
        self.obtain_calls = []
        self.wait_healthy_calls = []

    def wait_healthy(
        self,
        timeout_seconds=60,
        retry_interval_seconds=1,
        raise_exception=True,
        request_timeout_seconds=5,
        cancelled_fn=None,
    ):
        self.wait_healthy_calls.append(
            {
                "timeout_seconds": timeout_seconds,
                "retry_interval_seconds": retry_interval_seconds,
                "raise_exception": raise_exception,
                "request_timeout_seconds": request_timeout_seconds,
            }
        )
        if cancelled_fn is not None and cancelled_fn():
            return False
        if self.error:
            if not raise_exception:
                return False
            raise self.error
        return True

    def obtain(self, hosts, **kwargs):
        self.obtain_calls.append({"hosts": hosts, "kwargs": kwargs})
        if self.started:
            self.started.set()
        if self.release:
            self.release.wait(timeout=2)
        if self.error:
            raise self.error
        return self.response


class DummyRemoteSkipFailingClient(DummyRemoteClient):
    def obtain(self, hosts, **kwargs):
        self.obtain_calls.append({"hosts": hosts, "kwargs": kwargs})
        if kwargs.get("skip_failing", True):
            return CertificateResponse()
        raise RuntimeError("None of the domains are owned by this machine or could be verified")


class DummyKeyStore:
    def __init__(self):
        self._domain_map = {}
        self._keys_by_name = {}
        self._keys_by_id = {}
        self._certs_by_id = {}
        self.saved_keys = []
        self.saved_certs = []
        self._seq = 0

    def set_domain_cert(self, domain, cert_chain):
        self._domain_map[domain] = ("cert-id", "key", cert_chain)

    def find_key_and_cert_by_domain(self, domain):
        return self._domain_map.get(domain)

    def find_key_and_cert_by_cert_id(self, id):
        return self._certs_by_id.get(id)

    def save_key(self, key, name):
        self._seq += 1
        self.saved_keys.append((name, key))
        self._keys_by_name[name] = key
        self._keys_by_id[self._seq] = key
        return self._seq

    def find_key_by_name(self, name):
        return self._keys_by_name.get(name)

    def find_key_by_id(self, id):
        return self._keys_by_id.get(id)

    def save_cert(self, private_key_id, cert, domains, name=None):
        self.saved_certs.append((private_key_id, domains, name, cert))
        if name is not None:
            self._certs_by_id[name] = (private_key_id, self._keys_by_id.get(private_key_id), [cert])
        return "saved-cert-id"


def _make_cert_pem(domain: str, now: datetime, valid_for_days: int) -> str:
    key = Key.generate("ecdsa")
    csr = key.create_csr(domain=domain, alt_names=[domain])
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "pytest.certapi.local")]))
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=valid_for_days))
    )
    for ext in csr.extensions:
        cert_builder = cert_builder.add_extension(ext.value, ext.critical)
    cert = key.sign_csr(cert_builder)
    return cert_to_pem(cert).decode("utf-8")


def test_default_threshold_and_min_floor(monkeypatch):
    monkeypatch.delenv("CERT_RENEW_THRESHOLD_DAYS", raising=False)
    mgr = RenewalManager(DummyClient())
    assert mgr.renew_threshold_days == DEFAULT_RENEW_THRESHOLD_DAYS
    assert mgr.update_threshold_secs == DEFAULT_RENEW_THRESHOLD_DAYS * 24 * 3600
    assert mgr.cert_min_renew_threshold_secs == DEFAULT_RENEW_THRESHOLD_DAYS * 24 * 3600
    assert mgr._due_window_secs() == DEFAULT_RENEW_THRESHOLD_DAYS * 24 * 3600

    monkeypatch.setenv("CERT_RENEW_THRESHOLD_DAYS", "30")
    mgr_env = RenewalManager(DummyClient())
    assert mgr_env.renew_threshold_days == 30
    assert mgr_env.update_threshold_secs == 30 * 24 * 3600

    # Default floor is 10 days: lower thresholds should still use 10d renewal window.
    mgr_low = RenewalManager(DummyClient(), renew_threshold_days=5)
    assert mgr_low.update_threshold_secs == 5 * 24 * 3600
    assert mgr_low.cert_min_renew_threshold_secs == 10 * 24 * 3600
    assert mgr_low._due_window_secs() == 10 * 24 * 3600


def test_sleep_computation_slack_and_cap():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    mgr = RenewalManager(DummyClient(), renew_threshold_days=30)
    mgr.update_watch_domains(["example.com"])

    with mgr._lock:
        mgr._cache["example.com"] = now + timedelta(days=60)
    wait_seconds = mgr._compute_wait_seconds(now)
    assert wait_seconds == (30 * 24 * 3600 + 300)

    with mgr._lock:
        mgr._cache["example.com"] = now + timedelta(days=365)
    wait_seconds = mgr._compute_wait_seconds(now)
    assert wait_seconds == 32 * 24 * 3600


def test_wait_is_none_when_cache_empty():
    mgr = RenewalManager(DummyClient())
    assert mgr._compute_wait_seconds(datetime(2026, 1, 1, tzinfo=UTC)) is None


def test_existing_cert_failure_sets_threshold_plus_24h_retry():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    clock = {"now": now}
    client = DummyClient()
    client.set_handler("example.com", RuntimeError("renew failed"))

    mgr = RenewalManager(
        client,
        renew_threshold_days=30,
        clock_fn=lambda: clock["now"],
    )
    with mgr._lock:
        mgr._watch_domains = {"example.com"}
        mgr._cache["example.com"] = now - timedelta(hours=1)

    mgr.trigger_now()

    expected = now + timedelta(seconds=mgr.update_threshold_secs + mgr.renew_retry_interval_seconds)
    with mgr._lock:
        assert mgr._cache["example.com"] == expected
    assert len(client.calls) == 1


def test_existing_cert_failure_does_not_selfsign():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    key = Key.generate("ecdsa")
    csr = key.create_csr(domain="existing.example.com", alt_names=["existing.example.com"])
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "pytest.certapi.local")]))
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
    )
    for ext in csr.extensions:
        cert_builder = cert_builder.add_extension(ext.value, ext.critical)
    cert = key.sign_csr(cert_builder)

    client = DummyClient()
    client.key_store = DummyKeyStore()
    client.key_store.set_domain_cert("existing.example.com", [cert])
    client.set_handler("existing.example.com", RuntimeError("renew failed"))

    mgr = RenewalManager(client, renew_threshold_days=30, clock_fn=lambda: now)
    mgr.update_watch_domains(["existing.example.com"])
    with mgr._lock:
        mgr._cache["existing.example.com"] = now - timedelta(hours=1)

    mgr.trigger_now()

    assert len(client.calls) == 1
    assert client.key_store.saved_certs == []


def test_expired_local_cert_failure_keeps_existing_cert_and_defers_retry():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    key = Key.generate("ecdsa")
    csr = key.create_csr(domain="expired.example.com", alt_names=["expired.example.com"])
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "pytest.certapi.local")]))
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=10))
        .not_valid_after(now - timedelta(days=1))
    )
    for ext in csr.extensions:
        cert_builder = cert_builder.add_extension(ext.value, ext.critical)
    expired_cert = key.sign_csr(cert_builder)

    client = DummyClient()
    client.key_store = DummyKeyStore()
    client.key_store.set_domain_cert("expired.example.com", [expired_cert])
    client.set_handler("expired.example.com", RuntimeError("renew failed"))

    mgr = RenewalManager(client, renew_threshold_days=30, clock_fn=lambda: now)
    mgr.update_watch_domains(["expired.example.com"])

    expected = now + timedelta(seconds=mgr.update_threshold_secs + mgr.renew_retry_interval_seconds)
    with mgr._lock:
        assert mgr._cache["expired.example.com"] == expected
    assert len(client.calls) == 1
    assert client.key_store.saved_certs == []


def test_expired_sqlite_cert_failure_does_not_seed_selfsigned_as_fresh():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    key = Key.generate("ecdsa")
    csr = key.create_csr(domain="sqlite-expired.example.com", alt_names=["sqlite-expired.example.com"])
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "pytest.certapi.local")]))
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=10))
        .not_valid_after(now - timedelta(days=1))
    )
    for ext in csr.extensions:
        cert_builder = cert_builder.add_extension(ext.value, ext.critical)
    expired_cert = key.sign_csr(cert_builder)

    with TemporaryDirectory() as tmp_dir:
        key_store = SqliteKeyStore(f"{tmp_dir}/database.db")
        key_id = key_store.save_key(key, "sqlite-expired.example.com")
        key_store.save_cert(key_id, expired_cert, ["sqlite-expired.example.com"])

        client = DummyClient()
        client.key_store = key_store
        client.set_handler("sqlite-expired.example.com", RuntimeError("renew failed"))

        mgr = RenewalManager(client, renew_threshold_days=30, clock_fn=lambda: now)
        mgr.update_watch_domains(["sqlite-expired.example.com"])

        with mgr._lock:
            assert "sqlite-expired.example.com" in mgr._cache
            assert mgr._cache["sqlite-expired.example.com"] == now + timedelta(
                seconds=mgr.update_threshold_secs + mgr.renew_retry_interval_seconds
            )
        assert len(client.calls) == 1
        assert key_store.find_key_by_name("sqlite-expired.example.com.selfsigned") is None


def test_retry_deferral_suppresses_immediate_retry_and_force_when_blacklisted():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    clock = {"now": now}
    client = DummyClient()
    client.set_handler("retry.example.com", RuntimeError("renew failed"))

    mgr = RenewalManager(client, renew_threshold_days=30, clock_fn=lambda: clock["now"])
    mgr.update_watch_domains(["retry.example.com"])
    with mgr._lock:
        mgr._cache["retry.example.com"] = now - timedelta(minutes=1)

    mgr.trigger_now()
    assert len(client.calls) == 1

    # Normal run should not retry because cache got deferred to threshold+24h.
    mgr._run_cycle(force=False)
    assert len(client.calls) == 1

    # Force trigger still honors blacklist/backoff in nginx-proxy style behavior.
    mgr.trigger_now()
    assert len(client.calls) == 1


def test_watch_domain_replacement_drops_unwatched_cache_and_external_update_processes_new_set():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    client = DummyClient()
    cert_c = _make_cert_pem("c.example.com", now, valid_for_days=60)
    client.set_handler(
        "c.example.com",
        CertificateResponse(issued=[IssuedCert(cert=cert_c, domains=["c.example.com"])], existing=[]),
    )

    mgr = RenewalManager(client, clock_fn=lambda: now)
    mgr.update_watch_domains(["a.example.com", "b.example.com"])
    with mgr._lock:
        mgr._cache["a.example.com"] = now + timedelta(days=20)
        mgr._cache["b.example.com"] = now + timedelta(days=20)

    mgr.update_watch_domains(["a.example.com"])
    with mgr._lock:
        assert "b.example.com" not in mgr._cache

    # Integrations can publish new domain state directly, outside the timed
    # renewal callback path.
    mgr.update_watch_domains(["c.example.com"])
    state = mgr.get_state()
    assert state["watched_domains"] == ["c.example.com"]
    with mgr._lock:
        assert "a.example.com" not in mgr._cache
        assert "c.example.com" in mgr._cache


def test_bootstrap_and_cache_update_from_issued_and_existing():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    client = DummyClient()

    cert_issued = _make_cert_pem("issued.example.com", now, valid_for_days=65)
    cert_existing = _make_cert_pem("existing.example.com", now, valid_for_days=55)

    batched_response = CertificateResponse(
        issued=[IssuedCert(cert=cert_issued, domains=["issued.example.com"])],
        existing=[IssuedCert(cert=cert_existing, domains=["existing.example.com"])],
    )
    client.set_handler("issued.example.com", batched_response)
    client.set_handler("existing.example.com", batched_response)

    mgr = RenewalManager(client, renew_threshold_days=30, clock_fn=lambda: now)
    mgr.update_watch_domains(["issued.example.com", "existing.example.com"])

    # No cache initially; both should be obtained immediately to bootstrap.
    mgr._run_cycle(force=False)

    with mgr._lock:
        assert "issued.example.com" in mgr._cache
        assert "existing.example.com" in mgr._cache
    assert len(client.calls) == 1
    assert client.calls[0]["kwargs"]["renew_threshold_days"] == (mgr.cert_min_renew_threshold_secs // (24 * 3600))


def test_renewal_manager_prefers_obtain_when_available():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    client = DummyClientWithObtain()
    cert_issued = _make_cert_pem("prefer-obtain.example.com", now, valid_for_days=60)
    client.set_handler(
        "prefer-obtain.example.com",
        CertificateResponse(
            issued=[IssuedCert(cert=cert_issued, domains=["prefer-obtain.example.com"])],
            existing=[],
        ),
    )

    mgr = RenewalManager(client, renew_threshold_days=30, clock_fn=lambda: now)
    mgr.update_watch_domains(["prefer-obtain.example.com"])

    assert len(client.obtain_calls) == 1
    assert len(client.issue_calls) == 0


def test_renewal_manager_passes_typed_obtain_options_into_renewal_calls():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    client = DummyClient()
    cert = _make_cert_pem("batch.example.com", now, valid_for_days=60)
    client.set_handler(
        "batch.example.com",
        CertificateResponse(issued=[IssuedCert(cert=cert, domains=["batch.example.com"])], existing=[]),
    )

    mgr = RenewalManager(
        client,
        renew_threshold_days=30,
        clock_fn=lambda: now,
        batch_domains=True,
        self_verify=False,
        organization="certapi-tests",
    )
    mgr.update_watch_domains(["batch.example.com"])

    assert len(client.calls) == 1
    assert client.calls[0]["kwargs"]["batch_domains"] is True
    assert client.calls[0]["kwargs"]["self_verify"] is False
    assert client.calls[0]["kwargs"]["skip_failing"] is True
    assert client.calls[0]["kwargs"]["renew_threshold_days"] == 30
    assert client.calls[0]["kwargs"]["organization"] == "certapi-tests"


def test_local_keystore_seed_prevents_remote_call_when_fresh():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    key = Key.generate("ecdsa")
    csr = key.create_csr(domain="fresh.example.com", alt_names=["fresh.example.com"])
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

    client = DummyClient()
    client.key_store = DummyKeyStore()
    client.key_store.set_domain_cert("fresh.example.com", [cert])

    mgr = RenewalManager(client, renew_threshold_days=30, clock_fn=lambda: now)
    mgr.update_watch_domains(["fresh.example.com"])

    with mgr._lock:
        assert "fresh.example.com" in mgr._cache
    assert len(client.calls) == 0


def test_local_keystore_seed_stale_cert_still_renews():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    key = Key.generate("ecdsa")
    csr = key.create_csr(domain="stale.example.com", alt_names=["stale.example.com"])
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "pytest.certapi.local")]))
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=10))
        .not_valid_after(now + timedelta(days=3))
    )
    for ext in csr.extensions:
        cert_builder = cert_builder.add_extension(ext.value, ext.critical)
    stale_cert = key.sign_csr(cert_builder)

    renewed_cert = _make_cert_pem("stale.example.com", now, valid_for_days=60)
    client = DummyClient()
    client.key_store = DummyKeyStore()
    client.key_store.set_domain_cert("stale.example.com", [stale_cert])
    client.set_handler(
        "stale.example.com",
        CertificateResponse(issued=[IssuedCert(cert=renewed_cert, domains=["stale.example.com"])], existing=[]),
    )

    mgr = RenewalManager(client, renew_threshold_days=30, clock_fn=lambda: now)
    mgr.update_watch_domains(["stale.example.com"])

    assert len(client.calls) == 1
    with mgr._lock:
        assert "stale.example.com" in mgr._cache


def test_new_domain_failure_selfsigns_and_blacklists(capsys):
    now = datetime(2026, 1, 1, tzinfo=UTC)
    clock = {"now": now}
    client = DummyClient()
    client.key_store = DummyKeyStore()
    client.set_handler("new.example.com", RuntimeError("obtain failed"))

    mgr = RenewalManager(
        client,
        renew_threshold_days=30,
        blacklist_duration_seconds=180,
        clock_fn=lambda: clock["now"],
    )
    mgr.update_watch_domains(["new.example.com"])

    assert len(client.calls) == 1
    assert len(client.key_store.saved_certs) == 1
    assert client.key_store.saved_certs[0][2] == "new.example.com.selfsigned"
    output = capsys.readouterr().out
    assert "[CertApi] WARN [self-sign]: new.example.com" in output

    # Blacklist should suppress immediate retry.
    mgr._run_cycle(force=False)
    assert len(client.calls) == 1
    assert "new.example.com" in mgr.get_state()["blacklisted_domains"]

    # After blacklist expiry, retries are allowed again.
    clock["now"] = now + timedelta(seconds=181)
    mgr._run_cycle(force=False)
    assert len(client.calls) == 2


def test_multiple_new_domain_failures_log_one_selfsign_warning(capsys):
    now = datetime(2026, 1, 1, tzinfo=UTC)
    client = DummyClient()
    client.key_store = DummyKeyStore()
    client.set_handler("one.example.com", RuntimeError("obtain failed"))

    mgr = RenewalManager(client, renew_threshold_days=30, clock_fn=lambda: now)
    mgr._renew_domains(["one.example.com", "two.example.com", "three.example.com"], now)

    output = capsys.readouterr().out
    assert "[CertApi] WARN [self-sign]: one.example.com, two.example.com, three.example.com" in output
    assert output.count("WARN [self-sign]") == 1


def test_selfsigned_registration_rewrites_missing_cert_when_key_exists(capsys):
    client = DummyClient()
    client.key_store = DummyKeyStore()
    self_signed_name = "partial.example.com.selfsigned"
    client.key_store._keys_by_name[self_signed_name] = Key.generate("ecdsa")

    mgr = RenewalManager(client)
    mgr._register_self_signed("partial.example.com")

    assert len(client.key_store.saved_certs) == 1
    assert client.key_store.saved_certs[0][2] == self_signed_name
    output = capsys.readouterr().out
    assert "[CertApi] WARN [self-sign]: partial.example.com" in output


def test_partial_renewal_success_selfsigns_uncovered_domains(capsys):
    now = datetime(2026, 1, 1, tzinfo=UTC)
    client = DummyClient()
    client.key_store = DummyKeyStore()
    ok_cert = _make_cert_pem("ok.example.com", now, valid_for_days=60)
    client.set_handler(
        "ok.example.com",
        CertificateResponse(issued=[IssuedCert(cert=ok_cert, domains=["ok.example.com"])], existing=[]),
    )

    mgr = RenewalManager(client, renew_threshold_days=30, clock_fn=lambda: now)
    with mgr._lock:
        mgr._watch_domains = {"ok.example.com", "missing.example.com"}
    mgr._renew_domains(["ok.example.com", "missing.example.com"], now)

    with mgr._lock:
        assert "ok.example.com" in mgr._cache
    assert len(client.key_store.saved_certs) == 1
    assert client.key_store.saved_certs[0][2] == "missing.example.com.selfsigned"
    output = capsys.readouterr().out
    assert "[CertApi] Fetched 1 certificates: 1 new, 0 reused" in output
    assert "[CertApi] Issued certificates: ok.example.com" in output
    assert "[CertApi] WARN [unresolved]: missing.example.com" in output
    assert "[CertApi] WARN [self-sign]: missing.example.com" in output


def test_renewal_logs_fetched_certificate_summary(capsys):
    now = datetime(2026, 1, 1, tzinfo=UTC)
    client = DummyClient()
    new_cert = _make_cert_pem("new.example.com", now, valid_for_days=60)
    reused_cert = _make_cert_pem("reused.example.com", now, valid_for_days=60)
    response = CertificateResponse(
        issued=[IssuedCert(cert=new_cert, domains=["new.example.com"])],
        existing=[IssuedCert(cert=reused_cert, domains=["reused.example.com"])],
    )
    client.set_handler("new.example.com", response)
    client.set_handler("reused.example.com", response)

    mgr = RenewalManager(client, renew_threshold_days=30, clock_fn=lambda: now)
    mgr.update_watch_domains(["new.example.com", "reused.example.com"])

    output = capsys.readouterr().out
    assert "[CertApi] Fetched 2 certificates: 1 new, 1 reused" in output


def test_update_watch_domains_blocks_until_running_worker_processes_domains():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    started = threading.Event()
    release = threading.Event()
    client = DummyClient()
    cert = _make_cert_pem("requested.example.com", now, valid_for_days=90)

    def slow_handler(host, kwargs):
        started.set()
        release.wait(timeout=2)
        return CertificateResponse(issued=[IssuedCert(cert=cert, domains=[host])], existing=[])

    client.set_handler("requested.example.com", slow_handler)
    mgr = RenewalManager(client, clock_fn=lambda: now)
    mgr.start()

    update_thread = threading.Thread(target=lambda: mgr.update_watch_domains(["requested.example.com"]))
    update_thread.start()

    assert started.wait(timeout=2)
    assert update_thread.is_alive()
    release.set()
    update_thread.join(timeout=2)
    mgr.stop()

    assert not update_thread.is_alive()
    assert len(client.calls) == 1
    assert client.calls[0]["host"] == "requested.example.com"


def test_renewal_cycle_invokes_callback_and_callback_updates_domains():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    client = DummyClient()
    cert = _make_cert_pem("from-callback.example.com", now, valid_for_days=60)
    client.set_handler(
        "from-callback.example.com",
        CertificateResponse(issued=[IssuedCert(cert=cert, domains=["from-callback.example.com"])], existing=[]),
    )
    mgr = None

    def renewal_callback():
        mgr.update_watch_domains(["from-callback.example.com"])

    mgr = RenewalManager(client, renewal_callback=renewal_callback, clock_fn=lambda: now)
    mgr.trigger_now()

    with mgr._lock:
        assert mgr._watch_domains == {"from-callback.example.com"}
        assert "from-callback.example.com" in mgr._cache
        assert mgr._force_trigger is False
        assert mgr._cycle_requested is False
    assert len(client.calls) == 1


def test_start_does_not_invoke_callback_without_due_watched_cert():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    callback_called = threading.Event()

    mgr = RenewalManager(
        DummyClient(),
        renewal_callback=callback_called.set,
        renew_threshold_days=30,
        clock_fn=lambda: now,
    )

    mgr.start()
    try:
        assert not callback_called.wait(timeout=0.05)
    finally:
        mgr.stop()


def test_update_watch_domains_does_not_invoke_callback_for_fresh_cert():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    callback_called = threading.Event()
    client = DummyClient()
    client.key_store = DummyKeyStore()
    key = Key.generate("ecdsa")
    csr = key.create_csr(domain="fresh-callback.example.com", alt_names=["fresh-callback.example.com"])
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
    client.key_store.set_domain_cert("fresh-callback.example.com", [cert])

    mgr = RenewalManager(
        client,
        renewal_callback=callback_called.set,
        renew_threshold_days=30,
        clock_fn=lambda: now,
    )
    mgr.start()
    try:
        mgr.update_watch_domains(["fresh-callback.example.com"])
        assert not callback_called.wait(timeout=0.05)
    finally:
        mgr.stop()


def test_worker_invokes_callback_when_cached_cert_is_due():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    callback_called = threading.Event()
    mgr = RenewalManager(
        DummyClient(),
        renewal_callback=callback_called.set,
        renew_threshold_days=30,
        clock_fn=lambda: now,
    )
    with mgr._lock:
        mgr._watch_domains = {"due-callback.example.com"}
        mgr._cache["due-callback.example.com"] = now + timedelta(days=1)

    mgr.start()
    try:
        assert callback_called.wait(timeout=2)
    finally:
        mgr.stop()


def test_running_trigger_now_blocks_until_callback_update_finishes():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    obtain_started = threading.Event()
    release_obtain = threading.Event()
    client = DummyClient()
    cert = _make_cert_pem("blocking.example.com", now, valid_for_days=90)
    mgr = None

    def slow_handler(host, kwargs):
        obtain_started.set()
        release_obtain.wait(timeout=2)
        return CertificateResponse(issued=[IssuedCert(cert=cert, domains=[host])], existing=[])

    def renewal_callback():
        mgr.update_watch_domains(["blocking.example.com"])

    client.set_handler("blocking.example.com", slow_handler)
    mgr = RenewalManager(client, renewal_callback=renewal_callback, clock_fn=lambda: now)

    mgr.start()
    trigger_thread = threading.Thread(target=mgr.trigger_now)
    trigger_thread.start()

    assert obtain_started.wait(timeout=2)
    assert trigger_thread.is_alive()
    release_obtain.set()
    trigger_thread.join(timeout=2)

    mgr.stop()
    assert not trigger_thread.is_alive()
    assert len(client.calls) == 1
    assert client.calls[0]["host"] == "blocking.example.com"


def test_singleflight_suppresses_concurrent_manual_cycles():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    started = threading.Event()
    release = threading.Event()
    client = DummyClient()
    cert = _make_cert_pem("singleflight.example.com", now, valid_for_days=60)

    def slow_handler(host, kwargs):
        started.set()
        release.wait(timeout=2)
        return CertificateResponse(issued=[IssuedCert(cert=cert, domains=[host])], existing=[])

    client.set_handler("singleflight.example.com", slow_handler)
    mgr = RenewalManager(client, renew_threshold_days=30, clock_fn=lambda: now)
    with mgr._lock:
        mgr._watch_domains = {"singleflight.example.com"}

    first = threading.Thread(target=lambda: mgr.trigger_now())
    first.start()
    assert started.wait(timeout=2)

    second_result = mgr.trigger_now()
    release.set()
    first.join(timeout=2)

    assert second_result is None
    assert len(client.calls) == 1


def test_remote_certapi_polling_prints_waiting_message(capsys):
    now = datetime(2026, 1, 1, tzinfo=UTC)
    started = threading.Event()
    release = threading.Event()
    cert = _make_cert_pem("remote.example.com", now, valid_for_days=60)
    client = DummyRemoteClient(
        response=CertificateResponse(issued=[IssuedCert(cert=cert, domains=["remote.example.com"])], existing=[]),
        started=started,
        release=release,
    )
    mgr = RenewalManager(
        client,
        renew_threshold_days=30,
        remote_poll_interval_seconds=0.01,
        clock_fn=lambda: now,
    )
    with mgr._lock:
        mgr._watch_domains = {"remote.example.com"}

    thread = threading.Thread(target=lambda: mgr.trigger_now())
    thread.start()
    assert started.wait(timeout=2)
    time.sleep(0.03)
    release.set()
    thread.join(timeout=2)

    output = capsys.readouterr().out
    assert "[CertApi client] Requesting 1 certificate: remote.example.com" in output
    assert "[CertApi client] Waiting for certapi for" in output
    assert "[CertApi client] Fetched 1 certificates: 1 new, 0 reused" in output
    assert len(client.obtain_calls) == 1
    assert client.wait_healthy_calls == [
        {"timeout_seconds": 60, "retry_interval_seconds": 1, "raise_exception": True, "request_timeout_seconds": 5}
    ]


def test_remote_certapi_polling_defaults_to_ten_seconds():
    client = DummyRemoteClient()
    mgr = RenewalManager(client)

    assert mgr.remote_poll_interval_seconds == 10


def test_remote_renewal_uses_skip_failing_and_selfsigns_unresolved_domain():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    client = DummyRemoteSkipFailingClient()
    client.key_store = DummyKeyStore()

    mgr = RenewalManager(client, renew_threshold_days=30, clock_fn=lambda: now)
    mgr.update_watch_domains(["missing.example.com"])

    assert len(client.obtain_calls) == 1
    assert client.obtain_calls[0]["kwargs"]["skip_failing"] is True
    assert "missing.example.com" in mgr.get_state()["blacklisted_domains"]
    assert mgr.get_state()["last_error_message"] is None
    assert len(client.key_store.saved_certs) == 1
    assert client.key_store.saved_certs[0][2] == "missing.example.com.selfsigned"


def test_remote_renewal_logs_certapi_connection_error(capsys):
    now = datetime(2026, 1, 1, tzinfo=UTC)
    client = DummyRemoteClient(
        error=NetworkError(None, "CertAPI server is unreachable: GET https://certapi.local/api/health")
    )
    client.key_store = DummyKeyStore()

    mgr = RenewalManager(client, renew_threshold_days=30, clock_fn=lambda: now)
    mgr.update_watch_domains(["down.example.com"])

    output = capsys.readouterr().out
    assert (
        "[CertApi client] Renewal error: NetworkError: "
        "CertAPI server is unreachable: GET https://certapi.local/api/health"
    ) in output
    assert (
        mgr.get_state()["last_error_message"] == "CertAPI server is unreachable: GET https://certapi.local/api/health"
    )


def test_stop_does_not_wait_for_hung_remote_request_thread():
    started = threading.Event()
    release = threading.Event()
    client = DummyRemoteClient(started=started, release=release)
    mgr = RenewalManager(client, remote_poll_interval_seconds=0.01)
    with mgr._lock:
        mgr._watch_domains = {"hung.example.com"}

    mgr.start()
    mgr.trigger_now()
    assert started.wait(timeout=2)
    mgr.stop()

    assert not mgr._thread.is_alive()
    release.set()


def test_renewal_manager_batches_due_domains():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    client = DummyClientWithObtain()
    client.set_handler("domain1.com", CertificateResponse())

    mgr = RenewalManager(client, renew_threshold_days=30, clock_fn=lambda: now, batch_domains=True)
    mgr.update_watch_domains(["domain1.com", "domain2.com"])

    assert len(client.obtain_calls) == 1
    assert "domain1.com" in client.obtain_calls[0]["hosts"]
    assert "domain2.com" in client.obtain_calls[0]["hosts"]
