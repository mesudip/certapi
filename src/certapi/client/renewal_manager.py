import os
import threading
import time
from datetime import datetime, timezone, timedelta
from typing import Callable, Dict, Optional, Set, Any, List, Literal

from certapi.crypto import Key, certs_from_pem
from certapi.client.cert_manager_client import CertManagerClient
from certapi.issuers import SelfCertIssuer
from certapi.manager.acme_cert_manager import DEFAULT_RENEW_THRESHOLD_DAYS


class RenewalManager:
    """
    Background certificate refresh manager.

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
    """

    def __init__(
        self,
        cert_manager_client,
        sync_watch_domains: Optional[Callable[[], None]] = None,
        renew_threshold_days: Optional[int] = None,
        min_renew_threshold_days: int = 10,
        sleep_slack_seconds: int = 300,
        max_sleep_seconds: int = 32 * 24 * 3600,
        renew_retry_interval_seconds: int = 24 * 3600,
        blacklist_duration_seconds: int = 180,
        remote_poll_interval_seconds: int = 30,
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
        self.cert_manager_client = cert_manager_client
        self.sync_watch_domains = sync_watch_domains
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
        self._force_trigger = False
        self._cycle_running = False
        self._cycle_thread_id: Optional[int] = None
        self._blacklist: Dict[str, datetime] = {}
        self._last_error_message: Optional[str] = None
        self._last_error_timestamp: Optional[datetime] = None
        self._self_signer: Optional[SelfCertIssuer] = None

    def set_watch_domains(self, domains: List[str]):
        new_watch_set = {x for x in domains if x}
        with self._lock:
            self._watch_domains = new_watch_set
            self._cache = {d: expiry for d, expiry in self._cache.items() if d in self._watch_domains}
            self._blacklist = {d: exp for d, exp in self._blacklist.items() if d in self._watch_domains}
            if self._running and self._cycle_thread_id != threading.get_ident():
                self._force_trigger = True
            self._lock.notify_all()

    def start(self):
        with self._lock:
            if self._running:
                return
            self._running = True
            self._force_trigger = True
            self._thread = threading.Thread(target=self._worker, name="CertApi-RenewalManager", daemon=True)
            self._thread.start()

    def stop(self):
        thread = None
        with self._lock:
            self._running = False
            self._lock.notify_all()
            thread = self._thread

        if thread is not None and thread.is_alive():
            thread.join(timeout=2)

    def trigger_now(self):
        with self._lock:
            if self._running:
                self._force_trigger = True
                self._lock.notify_all()
                return
        self._run_cycle(force=True)

    def get_state(self) -> Dict[str, Any]:
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

    def _worker(self):
        while True:
            with self._lock:
                if not self._running:
                    return
                force = self._force_trigger
                self._force_trigger = False

            attempt_count = self._run_cycle(force=force)

            with self._lock:
                if not self._running:
                    return
                if self._force_trigger:
                    continue
                wait_seconds = self._compute_wait_seconds(self.clock_fn())

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

    def _sync_watch_domains(self):
        if self.sync_watch_domains is None:
            return
        try:
            self.sync_watch_domains()
        except Exception as e:
            self._set_error(e)

    def _due_window_secs(self) -> float:
        return max(self.update_threshold_secs, self.cert_min_renew_threshold_secs)

    def _compute_wait_seconds(self, now: datetime) -> Optional[float]:
        with self._lock:
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
                self._lock.notify_all()

    def _run_cycle_body(self, force: bool = False) -> int:
        self._sync_watch_domains()
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

        for domain in due_domains:
            self._renew_domain(domain, now)

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

    def _renew_domain(self, domain: str, now: datetime):
        domain_had_cached_entry = False
        with self._lock:
            domain_had_cached_entry = domain in self._cache

        try:
            renew_threshold_days = self.cert_min_renew_threshold_secs // (24 * 3600)
            obtain_options = {
                "key_type": self.key_type,
                "expiry_days": self.expiry_days,
                "renew_threshold_days": renew_threshold_days,
                "skip_failing": False,
                "batch_domains": self.batch_domains,
                "self_verify": self.self_verify,
                "country": self.country,
                "state": self.state,
                "locality": self.locality,
                "organization": self.organization,
                "user_id": self.user_id,
            }
            res = self._call_certificate_backend(
                self.cert_manager_client.obtain,
                [domain],
                obtain_options,
            )
            if res is None:
                return
            self._update_expiry_cache(res.issued + res.existing)
        except Exception as e:
            self._set_error(e)
            self._add_to_blacklist(domain, now)
            if domain_had_cached_entry or self._has_local_certificate(domain):
                self._schedule_existing_certificate_retry(domain, now)
            else:
                self._register_self_signed(domain)

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
        print("[Cert API Client] Requesting certificates:", ", ".join(domains))
        start_time = time.time()
        while thread.is_alive():
            thread.join(timeout=self.remote_poll_interval_seconds)
            with self._lock:
                running = self._running
            if stop_when_manager_stops and not running:
                return None
            if thread.is_alive():
                print(f"[Cert API Client] Waiting for response since {int(time.time() - start_time)} seconds")
        if exception:
            raise exception
        return result

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
                for domain in cert.domains:
                    if domain in self._watch_domains:
                        self._cache[domain] = expiry

            self._cache = {d: exp for d, exp in self._cache.items() if d in self._watch_domains}
            self._lock.notify_all()

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

    def _register_self_signed(self, domain: str):
        if self._has_local_certificate(domain):
            return

        key_store = getattr(self.cert_manager_client, "key_store", None)
        if key_store is None:
            return

        signer = self._get_or_create_self_signer()
        if signer is None:
            return

        try:
            self_signed_name = domain + ".selfsigned"
            if key_store.find_key_by_name(self_signed_name):
                return
            key, cert = signer.generate_key_and_cert_for_domain(domain, key_type="ecdsa")
            key_id = key_store.save_key(key, self_signed_name)
            key_store.save_cert(key_id, cert, [domain], name=self_signed_name)
        except Exception as e:
            self._set_error(e)
