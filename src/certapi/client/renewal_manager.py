import os
import threading
import time
from datetime import datetime, timezone, timedelta
from typing import Callable, Dict, Optional, Set, Any, List, Literal

from certapi.crypto import Key, certs_from_pem
from certapi.client.cert_manager_client import CertManagerClient
from certapi.domain_matching import domain_matches_cert_domain
from certapi.http.types import CertificateResponse
from certapi.issuers import SelfCertIssuer
from certapi.manager.acme_cert_manager import DEFAULT_RENEW_THRESHOLD_DAYS


class RenewalManager:
    """
    Keep certificates fresh for a changing set of watched domains.

    RenewalManager can run as a background worker with :meth:`start`, while
    callers publish the complete desired domain set through
    :meth:`update_watch_domains`. Publishing a domain set is synchronous: the call
    returns after certapi has processed the set and attempted any due
    obtain/renew work.

    The integration owns domain discovery. Certapi's background renewal cycle
    only invokes ``renewal_callback`` when it is time to refresh external state;
    that callback is responsible for calling :meth:`update_watch_domains` with
    the current complete domain set. ``update_watch_domains`` is the only method
    that mutates watched domains and performs due renewal work.

    Algorithm:
    - Maintain a watched domain set and cache each domain's certificate expiry.
    - Seed missing cache entries from the local keystore when a local certificate exists.
    - Attempt obtain/renew when a domain has no cached certificate, is forced, or its
      cached certificate expires inside the configured renewal window.
    - On successful obtain/renew, update the expiry cache from returned issued and
      existing certificates.
    - On failure for a new certificate, where no cached or local certificate exists,
      create and save a local self-signed certificate and temporarily blacklist the
      domain to avoid tight retry loops.
    - On failure for renewal, where a cached or local certificate exists, keep reusing
      that existing certificate even if it is expired, defer the next retry, and do not
      replace it with a self-signed certificate.

    The manager keeps an in-memory expiry cache, bootstraps that cache from the
    backend keystore when possible, renews missing or soon-expiring
    certificates, and records failures in :meth:`get_state`. New domains that
    fail issuance receive a short-lived retry blacklist and, when the backend
    exposes a keystore, a local self-signed fallback certificate. Renewal
    failures for domains with an existing certificate keep using that
    certificate and schedule a later retry.
    """

    def __init__(
        self,
        cert_manager_client,
        renewal_callback: Optional[Callable[[], None]] = None,
        renew_threshold_days: Optional[int] = None,
        min_renew_threshold_days: int = 10,
        sleep_slack_seconds: int = 300,
        max_sleep_seconds: int = 32 * 24 * 3600,
        renew_retry_interval_seconds: int = 24 * 3600,
        blacklist_duration_seconds: int = 180,
        remote_poll_interval_seconds: int = 10,
        remote_startup_health_timeout_seconds: int = 60,
        clock_fn: Optional[Callable[[], datetime]] = None,
        sleep_fn: Optional[Callable[[float], None]] = None,
        key_type: Literal["rsa", "ecdsa", "ed25519"] = "ecdsa",
        expiry_days: int = 90,
        batch_domains: bool = False,
        self_verify: bool = True,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        """
        Create a renewal manager for a certificate backend.

        Args:
            cert_manager_client: Backend object with an ``obtain(domains,
                **kwargs)`` method. Local managers and ``CertManagerClient`` are
                both supported.
            renewal_callback: Optional callback invoked by background or forced
                renewal cycles. Integrations should use this to recompute their
                domain list and call :meth:`update_watch_domains`. The callback
                itself should not perform certificate issuance directly.
            renew_threshold_days: Renew certificates when they expire within
                this many days. Defaults to ``CERT_RENEW_THRESHOLD_DAYS`` or the
                certapi default.
            min_renew_threshold_days: Lower bound for renewal attempts, used to
                avoid renewing too close to expiry even when a smaller threshold
                is configured.
            sleep_slack_seconds: Extra delay added after the calculated next
                renewal time to avoid waking exactly on the threshold boundary.
            max_sleep_seconds: Maximum time the background worker sleeps between
                checks.
            renew_retry_interval_seconds: Delay before retrying renewal for a
                domain that already has a local certificate.
            blacklist_duration_seconds: Delay before retrying issuance for a
                domain that had no usable local certificate.
            remote_poll_interval_seconds: Poll interval while waiting for remote
                ``CertManagerClient`` requests.
            remote_startup_health_timeout_seconds: How long to wait for a
                remote ``CertManagerClient`` to become healthy before the first
                request.
            clock_fn: Optional clock override for deterministic tests.
            sleep_fn: Optional sleep override for deterministic tests.
            key_type: Private key type requested from the backend.
            expiry_days: Requested certificate lifetime when the backend
                supports it.
            batch_domains: Forwarded to the backend to enable domain batching.
            self_verify: Forwarded to the backend to enable or disable
                ownership self-verification.
            country: Optional subject country for issued or fallback certs.
            state: Optional subject state for issued or fallback certs.
            locality: Optional subject locality for issued or fallback certs.
            organization: Optional subject organization for issued or fallback
                certs.
            user_id: Optional subject/user identifier for issued or fallback
                certs.
        """
        self.cert_manager_client = cert_manager_client
        self.renewal_callback = renewal_callback
        self.key_type = key_type
        self.expiry_days = expiry_days
        self.batch_domains = batch_domains
        self.self_verify = self_verify
        self.country = country
        self.state = state
        self.locality = locality
        self.organization = organization
        self.user_id = user_id
        self.sleep_slack_seconds = sleep_slack_seconds
        self.max_sleep_seconds = max_sleep_seconds
        self.renew_retry_interval_seconds = renew_retry_interval_seconds
        self.blacklist_duration_seconds = blacklist_duration_seconds
        self.remote_poll_interval_seconds = remote_poll_interval_seconds
        self.remote_startup_health_timeout_seconds = remote_startup_health_timeout_seconds
        self.clock_fn = clock_fn or (lambda: datetime.now(timezone.utc))
        self.sleep_fn = sleep_fn

        env_threshold = os.getenv("CERT_RENEW_THRESHOLD_DAYS")
        if renew_threshold_days is None:
            renew_threshold_days = int(env_threshold.strip()) if env_threshold else DEFAULT_RENEW_THRESHOLD_DAYS

        self.renew_threshold_days = renew_threshold_days
        self.min_renew_threshold_days = min_renew_threshold_days

        self.update_threshold_secs = self.renew_threshold_days * 24 * 3600
        self.cert_min_renew_threshold_secs = max(
            self.update_threshold_secs,
            self.min_renew_threshold_days * 24 * 3600,
        )

        self._watch_domains: Set[str] = set()
        self._cache: Dict[str, datetime] = {}
        self._lock = threading.Condition()
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._cycle_requested = False
        self._force_trigger = False
        self._cycle_running = False
        self._cycle_thread_id: Optional[int] = None
        self._cycle_generation = 0
        self._renewal_running = False
        self._renewal_requested = False
        self._renewal_thread_id: Optional[int] = None
        self._renewal_generation = 0
        self._blacklist: Dict[str, datetime] = {}
        self._last_error_message: Optional[str] = None
        self._last_error_timestamp: Optional[datetime] = None
        self._self_signer: Optional[SelfCertIssuer] = None
        self._remote_health_checked = False

    def update_watch_domains(self, domains: List[str]):
        """
        Replace the complete set of domains and process it before returning.

        Empty values are ignored. Cache and blacklist entries for domains no
        longer being watched are dropped.

        This method immediately runs or queues a renewal pass and blocks until
        certapi has attempted any due obtain/renew work for the latest published
        set. Concurrent calls are serialized inside the manager; if a renewal
        pass is already running, the current pass is allowed to finish and a
        follow-up pass processes the newest watch set before callers return.
        """
        new_watch_set = {x for x in domains if x}
        with self._lock:
            self._watch_domains = new_watch_set
            self._cache = {d: expiry for d, expiry in self._cache.items() if d in self._watch_domains}
            self._blacklist = {d: exp for d, exp in self._blacklist.items() if d in self._watch_domains}
            self._lock.notify_all()

        self._run_renewal_pass(force=False)

    def start(self):
        """
        Start the background renewal worker.

        The worker sleeps until the next watched certificate approaches the
        renewal threshold or until another thread publishes a new set with
        :meth:`update_watch_domains`.
        Calling ``start`` while already running is a no-op.
        """
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(target=self._worker, name="CertApi-RenewalManager", daemon=True)
            self._thread.start()

    def stop(self):
        """
        Stop the background renewal worker and wait briefly for it to exit.

        In-flight remote certificate requests run in daemon helper threads and
        are not waited on indefinitely; the manager stops scheduling new work
        and joins the worker thread for up to two seconds.
        """
        thread = None
        with self._lock:
            self._running = False
            self._lock.notify_all()
            thread = self._thread

        if thread is not None and thread.is_alive():
            thread.join(timeout=2)

    def trigger_now(self):
        """
        Run the renewal trigger immediately.

        When a renewal callback is configured, this method invokes that callback
        and waits for it to return. The callback should call
        :meth:`update_watch_domains`, which performs due renewal work. Without a
        callback, this method performs a direct forced renewal pass over the
        existing watch set.

        If called from inside the renewal cycle itself, the method only requests
        a follow-up pass and returns immediately to avoid deadlock.
        """
        with self._lock:
            if self._running:
                if self._cycle_thread_id == threading.get_ident():
                    self._force_trigger = True
                    self._lock.notify_all()
                    return
                target_generation = self._cycle_generation + (2 if self._cycle_running else 1)
                self._force_trigger = True
                self._lock.notify_all()
                while self._running and self._cycle_generation < target_generation:
                    self._lock.wait()
                return
        self._run_cycle(force=True)

    def get_state(self) -> Dict[str, Any]:
        """
        Return a snapshot of renewal-manager state for diagnostics.

        The returned dictionary includes watched domains, cache size, active
        blacklisted domains, next cached expiry time, whether the background
        worker is running, and the most recent error message/timestamp recorded
        by the manager.
        """
        with self._lock:
            next_renewal_time = min(self._cache.values()).isoformat() if self._cache else None
            return {
                "watched_domains": sorted(self._watch_domains),
                "cache_size": len(self._cache),
                "blacklisted_domains": sorted(self._active_blacklisted_domains(self.clock_fn())),
                "next_renewal_time": next_renewal_time,
                "running": self._running,
                "last_error_timestamp": self._last_error_timestamp.isoformat() if self._last_error_timestamp else None,
                "last_error_message": self._last_error_message,
            }

    def _set_error(self, error: Exception):
        self._last_error_message = str(error)
        self._last_error_timestamp = self.clock_fn()
        print(f"{self._log_prefix()} Renewal error: {error.__class__.__name__}: {error}")

    def _log_prefix(self) -> str:
        if isinstance(self.cert_manager_client, CertManagerClient):
            return "[CertApi client]"
        return "[CertApi]"

    def _worker(self):
        while True:
            with self._lock:
                if not self._running:
                    return
                force = self._force_trigger
                self._force_trigger = False
                cycle_requested = self._cycle_requested
                self._cycle_requested = False

                if not force and not cycle_requested:
                    wait_seconds = self._compute_wait_seconds_locked(self.clock_fn())
                    if wait_seconds is None:
                        self._lock.wait()
                        continue
                    if wait_seconds > 0:
                        self._lock.wait(wait_seconds)
                        continue

            attempt_count = self._run_cycle(force=force)

            with self._lock:
                if not self._running:
                    return
                if self._force_trigger or self._cycle_requested:
                    continue
                wait_seconds = self._compute_wait_seconds_locked(self.clock_fn())

                # Avoid tight loops in cases where nothing was attempted and no wait was computed.
                if (wait_seconds is not None and wait_seconds <= 0) and attempt_count == 0:
                    wait_seconds = 1

            self._wait(wait_seconds)

    def _wait(self, wait_seconds: Optional[float]):
        with self._lock:
            if not self._running:
                return

            if wait_seconds is None:
                self._lock.wait()
                return

        if self.sleep_fn is None:
            with self._lock:
                if self._running:
                    self._lock.wait(wait_seconds)
            return

        # Testing hook: allows deterministic no-op sleep behavior.
        self.sleep_fn(wait_seconds)

    def _due_window_secs(self) -> float:
        return max(self.update_threshold_secs, self.cert_min_renew_threshold_secs)

    def _compute_wait_seconds(self, now: datetime) -> Optional[float]:
        with self._lock:
            return self._compute_wait_seconds_locked(now)

    def _compute_wait_seconds_locked(self, now: datetime) -> Optional[float]:
        if not self._cache:
            return None
        next_ssl_expiry = min(self._cache.values())
        remaining_seconds = (next_ssl_expiry - now).total_seconds()
        if remaining_seconds > self.update_threshold_secs:
            return min(
                remaining_seconds - self.update_threshold_secs + self.sleep_slack_seconds,
                self.max_sleep_seconds,
            )
        return 0

    def _run_cycle(self, force: bool = False) -> int:
        with self._lock:
            if self._cycle_running:
                if force:
                    self._force_trigger = True
                    self._lock.notify_all()
                return 0
            self._cycle_running = True
            self._cycle_thread_id = threading.get_ident()

        try:
            return self._run_cycle_body(force=force)
        finally:
            with self._lock:
                self._cycle_running = False
                self._cycle_thread_id = None
                self._cycle_generation += 1
                self._lock.notify_all()

    def _run_cycle_body(self, force: bool = False) -> int:
        if self.renewal_callback is None:
            return self._run_renewal_pass(force=force)

        try:
            self.renewal_callback()
        except Exception as e:
            self._set_error(e)
        return 0

    def _run_renewal_pass(self, force: bool = False) -> int:
        count = 0
        current_thread_id = threading.get_ident()
        with self._lock:
            if self._renewal_thread_id == current_thread_id:
                return 0
            if self._renewal_running:
                target_generation = self._renewal_generation + 2
                self._renewal_requested = True
                self._lock.notify_all()
                while self._renewal_generation < target_generation:
                    self._lock.wait()
                return 0

            self._renewal_running = True
            self._renewal_thread_id = current_thread_id

        try:
            while True:
                count += self._run_renewal_pass_body(force=force)
                with self._lock:
                    self._renewal_generation += 1
                    if not self._renewal_requested:
                        return count
                    self._renewal_requested = False
                    force = False
                    self._lock.notify_all()
        finally:
            with self._lock:
                self._renewal_running = False
                self._renewal_thread_id = None
                self._lock.notify_all()

    def _run_renewal_pass_body(self, force: bool = False) -> int:
        self._seed_cache_from_local_keystore()
        now = self.clock_fn()
        self._clean_blacklist(now)
        due_window = self._due_window_secs()

        with self._lock:
            watched = list(self._watch_domains)
            cached = dict(self._cache)

        due_domains: List[str] = []
        for domain in watched:
            if self._is_blacklisted(domain, now):
                continue
            expiry = cached.get(domain)
            if expiry is None:
                due_domains.append(domain)
                continue
            if force:
                due_domains.append(domain)
                continue
            if (expiry - now).total_seconds() < due_window:
                due_domains.append(domain)

        if due_domains:
            self._renew_domains(due_domains, now)

        return len(due_domains)

    def _seed_cache_from_local_keystore(self):
        key_store = getattr(self.cert_manager_client, "key_store", None)
        if key_store is None:
            return

        with self._lock:
            missing_domains = [d for d in self._watch_domains if d not in self._cache]

        if not missing_domains:
            return

        now = self.clock_fn()
        loaded: Dict[str, datetime] = {}

        for domain in missing_domains:
            try:
                result = key_store.find_key_and_cert_by_domain(domain)
                if result is None:
                    continue
                certs = result[2] if len(result) > 2 else None
                if not certs:
                    continue
                leaf_cert = certs[0]
                expiry = getattr(leaf_cert, "not_valid_after_utc", None)
                if expiry is None or expiry <= now:
                    continue
                loaded[domain] = expiry
            except Exception as e:
                self._set_error(e)

        if not loaded:
            return

        with self._lock:
            for domain, expiry in loaded.items():
                if domain in self._watch_domains:
                    self._cache[domain] = expiry
            self._lock.notify_all()

    def _renew_domains(self, domains: List[str], now: datetime):
        domains_with_cached_entries = []
        with self._lock:
            for domain in domains:
                if domain in self._cache:
                    domains_with_cached_entries.append(domain)

        try:
            renew_threshold_days = self.cert_min_renew_threshold_secs // (24 * 3600)
            obtain_options = {
                "key_type": self.key_type,
                "expiry_days": self.expiry_days,
                "renew_threshold_days": renew_threshold_days,
                # Renewal should obtain whatever can be issued, then self-sign unresolved domains.
                "skip_failing": True,
                "batch_domains": True,
                "self_verify": self.self_verify,
                "country": self.country,
                "state": self.state,
                "locality": self.locality,
                "organization": self.organization,
                "user_id": self.user_id,
            }
            res = self._call_certificate_backend(
                self.cert_manager_client.obtain,
                domains,
                obtain_options,
            )
            if res is None:
                return
            certs = res.issued + res.existing
            self._log_certificate_fetch_summary(res)
            self._log_certificate_results(res.issued, "Issued certificates")
            self._log_failed_batches(res)
            self._update_expiry_cache(certs)
            covered_domains = self._covered_domains_from_response(certs)
            unresolved_domains = [domain for domain in domains if domain not in covered_domains]
            self._log_unresolved_domains(unresolved_domains)
            self_signed_domains = []
            for domain in unresolved_domains:
                self._add_to_blacklist(domain, now)
                if domain in domains_with_cached_entries or self._has_local_certificate(domain):
                    self._schedule_existing_certificate_retry(domain, now)
                else:
                    if self._register_self_signed(domain, log=False):
                        self_signed_domains.append(domain)
            self._log_self_signed_domains(self_signed_domains)
        except Exception as e:
            self._set_error(e)
            self_signed_domains = []
            for domain in domains:
                self._add_to_blacklist(domain, now)
                if domain in domains_with_cached_entries or self._has_local_certificate(domain):
                    self._schedule_existing_certificate_retry(domain, now)
                else:
                    if self._register_self_signed(domain, log=False):
                        self_signed_domains.append(domain)
            self._log_self_signed_domains(self_signed_domains)

    def _schedule_existing_certificate_retry(self, domain: str, now: datetime):
        retry_interval_seconds = min(self.renew_retry_interval_seconds, 24 * 3600)
        with self._lock:
            self._cache[domain] = now + timedelta(seconds=self.update_threshold_secs + retry_interval_seconds)
            self._lock.notify_all()

    def _call_certificate_backend(self, fn, domains: List[str], kwargs: Dict[str, Any]):
        if not isinstance(self.cert_manager_client, CertManagerClient):
            return fn(domains, **kwargs)

        result = None
        exception = None
        with self._lock:
            stop_when_manager_stops = self._running

        if not self._wait_for_remote_health_once(stop_when_manager_stops=stop_when_manager_stops):
            return None

        def worker():
            nonlocal result, exception
            try:
                result = fn(domains, **kwargs)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                exception = e

        thread = threading.Thread(target=worker, name="CertApi-RenewalManager-RemoteRequest", daemon=True)
        thread.start()
        certificate_label = "certificate" if len(domains) == 1 else "certificates"
        print(f"{self._log_prefix()} Requesting {len(domains)} {certificate_label}: {', '.join(domains)}")
        start_time = time.time()
        while thread.is_alive():
            thread.join(timeout=self.remote_poll_interval_seconds)
            with self._lock:
                running = self._running
            if stop_when_manager_stops and not running:
                return None
            if thread.is_alive():
                print(f"{self._log_prefix()} Waiting for certapi for {int(time.time() - start_time)} secs")
        if exception:
            raise exception
        return result

    def _wait_for_remote_health_once(self, stop_when_manager_stops: bool = False) -> bool:
        with self._lock:
            if self._remote_health_checked:
                return True

        def cancelled():
            if not stop_when_manager_stops:
                return False
            with self._lock:
                return not self._running

        healthy = self.cert_manager_client.wait_healthy(
            self.remote_startup_health_timeout_seconds,
            raise_exception=True,
            cancelled_fn=cancelled,
        )
        if not healthy:
            return False
        with self._lock:
            self._remote_health_checked = True
        return True

    def _update_expiry_cache(self, certs):
        now = self.clock_fn()
        with self._lock:
            for cert in certs:
                cert_pem = cert.certificate
                if not cert_pem:
                    continue
                cert_chain = certs_from_pem(cert_pem.encode("utf-8"))
                if not cert_chain:
                    continue
                expiry = cert_chain[0].not_valid_after_utc
                # Guard against stale parse values.
                if expiry <= now:
                    continue
                for watched_domain in self._watch_domains:
                    if any(domain_matches_cert_domain(domain, watched_domain) for domain in cert.domains if domain):
                        self._cache[watched_domain] = expiry

            self._cache = {d: exp for d, exp in self._cache.items() if d in self._watch_domains}
            self._lock.notify_all()

    def _covered_domains_from_response(self, certs) -> Set[str]:
        covered: Set[str] = set()
        for cert in certs:
            for domain in cert.domains:
                if domain:
                    covered.add(domain)
                    for watched_domain in self._watch_domains:
                        if domain_matches_cert_domain(domain, watched_domain):
                            covered.add(watched_domain)
        return covered

    def _log_certificate_results(self, certs, label: str):
        if not certs:
            return
        certificates = []
        for cert in certs:
            domains = [domain for domain in cert.domains if domain]
            if domains:
                certificates.append(", ".join(domains))
        if certificates:
            print(f"{self._log_prefix()} {label}: {'; '.join(certificates)}")

    def _log_certificate_fetch_summary(self, response: CertificateResponse):
        issued_count = len(response.issued)
        existing_count = len(response.existing)
        total_count = issued_count + existing_count
        print(
            f"{self._log_prefix()} Fetched {total_count} certificates: " f"{issued_count} new, {existing_count} reused"
        )

    def _log_failed_batches(self, response: CertificateResponse):
        for failure in getattr(response, "failed", []):
            step = f" @ {failure.step}" if failure.step else ""
            print(
                f"{self._log_prefix()} ERROR [{', '.join(failure.domains)}]:"
                f" {failure.name}{step}: {failure.message}"
            )

    def _log_unresolved_domains(self, domains: List[str]):
        if domains:
            print(f"{self._log_prefix()} WARN [unresolved]: {', '.join(domains)}")

    def _log_self_signed_domains(self, domains: List[str]):
        if domains:
            print(f"{self._log_prefix()} WARN [self-sign]: {', '.join(domains)}")

    def _add_to_blacklist(self, domain: str, now: datetime):
        with self._lock:
            self._blacklist[domain] = now + timedelta(seconds=self.blacklist_duration_seconds)

    def _active_blacklisted_domains(self, now: datetime) -> List[str]:
        return [d for d, expiry in self._blacklist.items() if expiry > now]

    def _clean_blacklist(self, now: datetime):
        with self._lock:
            self._blacklist = {d: exp for d, exp in self._blacklist.items() if exp > now}

    def _is_blacklisted(self, domain: str, now: datetime) -> bool:
        with self._lock:
            expiry = self._blacklist.get(domain)
        return expiry is not None and expiry > now

    def _has_local_certificate(self, domain: str) -> bool:
        key_store = getattr(self.cert_manager_client, "key_store", None)
        if key_store is None:
            return False
        try:
            return key_store.find_key_and_cert_by_domain(domain) is not None
        except Exception as e:
            self._set_error(e)
            return False

    def _has_named_certificate(self, name: str) -> bool:
        key_store = getattr(self.cert_manager_client, "key_store", None)
        if key_store is None:
            return False
        try:
            return key_store.find_key_and_cert_by_cert_id(name) is not None
        except Exception as e:
            self._set_error(e)
            return False

    def _get_or_create_self_signer(self) -> Optional[SelfCertIssuer]:
        if self._self_signer is not None:
            return self._self_signer

        key_store = getattr(self.cert_manager_client, "key_store", None)
        if key_store is None:
            return None

        try:
            account_key = key_store.find_key_by_name("acme_account")
            if account_key is None:
                account_key = Key.generate("ecdsa")
                key_store.save_key(account_key, "acme_account")
            self._self_signer = SelfCertIssuer(
                account_key,
                "NP",
                "Bagmati",
                "Buddhanagar",
                "certapi-client",
                "local.certapi.client",
            )
            return self._self_signer
        except Exception as e:
            self._set_error(e)
            return None

    def _register_self_signed(self, domain: str, log: bool = True) -> bool:
        if self._has_local_certificate(domain):
            return False

        key_store = getattr(self.cert_manager_client, "key_store", None)
        if key_store is None:
            return False

        signer = self._get_or_create_self_signer()
        if signer is None:
            return False

        try:
            self_signed_name = domain + ".selfsigned"
            if self._has_named_certificate(self_signed_name):
                return False
            key, cert = signer.generate_key_and_cert_for_domain(domain, key_type="ecdsa")
            key_id = key_store.save_key(key, self_signed_name)
            key_store.save_cert(key_id, cert, [domain], name=self_signed_name)
            if log:
                self._log_self_signed_domains([domain])
            return True
        except Exception as e:
            self._set_error(e)
            return False
