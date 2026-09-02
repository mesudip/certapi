import time
from typing import Callable, List, Literal, Optional, Tuple, Union, Dict
from datetime import datetime, timezone, timedelta

from certapi import crypto
from ..acme import Challenge
from ..challenge_solver import ChallengeSolver
from ..errors import CertApiException

from ..issuers import AcmeCertIssuer, CertIssuer
from ..http.types import CertificateResponse, FailedDomains, IssuedCert
from ..keystore.KeyStore import KeyStore
from cryptography.x509 import Certificate, CertificateSigningRequest
from ..crypto import Key, certs_to_pem, cert_to_pem, get_csr_hostnames
from ..domain_batching import create_safe_domain_batches
from ..domain_matching import domain_matches_cert_domain, is_wildcard_domain, normalize_domain

DEFAULT_RENEW_THRESHOLD_DAYS = 62


class AcmeCertManager:
    def __init__(
        self,
        key_store: KeyStore,
        cert_issuer: AcmeCertIssuer,
        challenge_solvers: List[ChallengeSolver] = [],
        renew_threshold_days: int = DEFAULT_RENEW_THRESHOLD_DAYS,
    ):
        self.key_store: KeyStore = key_store
        self.cert_issuer: AcmeCertIssuer = cert_issuer
        self.challenge_solvers: List[ChallengeSolver] = challenge_solvers
        self.renew_threshold_days: int = (
            DEFAULT_RENEW_THRESHOLD_DAYS if renew_threshold_days is None else renew_threshold_days
        )

    def setup(self):
        names = [solver.__class__.__name__.replace("ChallengeSolver", "") for solver in self.challenge_solvers]
        print(f"AcmeCertManager started with  challenge_solvers: {names}")
        self.cert_issuer.setup()

    def issue_certificate_for_csr(self, csr: CertificateSigningRequest) -> str:
        """
        Returns Certificate
        """
        hostnames = get_csr_hostnames(csr)
        if not hostnames:
            raise ValueError("CSR does not contain any hostnames.")

        # Find a challenge solver that supports all hostnames in the CSR
        selected_challenge_solver = None
        for store in self.challenge_solvers:
            if all(store.supports_domain(h) for h in hostnames):
                selected_challenge_solver = store
                break

        if selected_challenge_solver is None:
            raise ValueError(f"No challenge solver found that supports all domains: {hostnames}")

        fullchain_cert = self.cert_issuer.sign_csr(csr, challenge_solver=selected_challenge_solver)
        if fullchain_cert:
            # Assuming the private key associated with the CSR is not managed by CertManager directly
            # and is handled by the caller or the cert_issuer's internal process.
            # For now, we'll just return the certificate.
            # If key saving is required here, the private key would need to be passed along with the CSR.
            return fullchain_cert
        else:
            return None

    def issue_certificate(
        self,
        hosts: Union[str, List[str]],
        key_type: Literal["rsa", "ecdsa", "ed25519"] = "ecdsa",
        expiry_days: int = 90,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        user_id: Optional[str] = None,
        renew_threshold_days: Optional[int] = None,
        skip_failing: bool = True,
        batch_domains: bool = False,
        self_verify: bool = True,
    ) -> CertificateResponse:
        return self.obtain(
            hosts=hosts,
            key_type=key_type,
            expiry_days=expiry_days,
            country=country,
            state=state,
            locality=locality,
            organization=organization,
            user_id=user_id,
            renew_threshold_days=renew_threshold_days,
            skip_failing=skip_failing,
            batch_domains=batch_domains,
            self_verify=self_verify,
        )

    def obtain(
        self,
        hosts: Union[str, List[str]],
        key_type: Literal["rsa", "ecdsa", "ed25519"] = "ecdsa",
        expiry_days: int = 90,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        user_id: Optional[str] = None,
        renew_threshold_days: Optional[int] = None,
        skip_failing: bool = True,
        batch_domains: bool = False,
        self_verify: bool = True,
    ) -> CertificateResponse:
        return self._issue_certificate_internal(
            hosts=hosts,
            key_type=key_type,
            expiry_days=expiry_days,
            country=country,
            state=state,
            locality=locality,
            organization=organization,
            user_id=user_id,
            renew_threshold_days=renew_threshold_days,
            batch_generator=create_safe_domain_batches if batch_domains else None,
            skip_failing=skip_failing,
            self_verify=self_verify,
        )

    def issue_certificate_in_batches(
        self,
        hosts: Union[str, List[str]],
        key_type: Literal["rsa", "ecdsa", "ed25519"] = "ecdsa",
        expiry_days: int = 90,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        user_id: Optional[str] = None,
        renew_threshold_days: Optional[int] = None,
        batch_generator: Callable[[List[str]], List[List[str]]] = create_safe_domain_batches,
        skip_failing: bool = True,
        self_verify: bool = True,
    ) -> CertificateResponse:
        return self._issue_certificate_internal(
            hosts=hosts,
            key_type=key_type,
            expiry_days=expiry_days,
            country=country,
            state=state,
            locality=locality,
            organization=organization,
            user_id=user_id,
            renew_threshold_days=renew_threshold_days,
            batch_generator=batch_generator,
            skip_failing=skip_failing,
            self_verify=self_verify,
        )

    def _issue_certificate_internal(
        self,
        hosts: Union[str, List[str]],
        key_type: Literal["rsa", "ecdsa", "ed25519"] = "ecdsa",
        expiry_days: int = 90,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        user_id: Optional[str] = None,
        renew_threshold_days: Optional[int] = None,
        batch_generator: Optional[Callable[[List[str]], List[List[str]]]] = None,
        skip_failing: bool = True,
        self_verify: bool = True,
    ) -> CertificateResponse:
        if isinstance(hosts, str):
            hosts = [hosts]

        normalized_hosts: List[str] = []
        seen_hosts: set[str] = set()
        for host in hosts:
            normalized = normalize_domain(host)
            if not normalized or normalized in seen_hosts:
                continue
            seen_hosts.add(normalized)
            normalized_hosts.append(normalized)
        hosts = normalized_hosts

        existing: Dict[str, Tuple[int | str, Key, List[Certificate] | str]] = {}
        for h in hosts:
            if hasattr(self.key_store, "find_key_and_cert_covering_domain"):
                covering_result = self.key_store.find_key_and_cert_covering_domain(h)
            else:
                result = self.key_store.find_key_and_cert_by_domain(h)
                covering_result = (h, result[0], result[1], result[2]) if result is not None else None
            if covering_result is not None:
                # covering_result is (matched_domain, domain_id, key, cert_list)
                matched_domain, cert_id, key, cert_list = covering_result
                cert = cert_list[0]
                invalid_date = cert.not_valid_after_utc
                # Check if the certificate is still valid for at least renew_threshold_days
                threshold = renew_threshold_days if renew_threshold_days is not None else self.renew_threshold_days
                if invalid_date > datetime.now(timezone.utc) + timedelta(days=threshold):
                    existing[matched_domain] = (cert_id, key, cert_list)
        missing = [
            h for h in hosts if not any(domain_matches_cert_domain(existing_domain, h) for existing_domain in existing)
        ]
        if len(missing) > 0:
            issued_certs_list = []
            # Group missing hosts by the challenge solver that supports them
            domains_by_store: Dict[ChallengeSolver, List[str]] = {}
            for host in missing:
                found_store = None
                for store in self.challenge_solvers:
                    supports_domain = (
                        store.supports_domain_strict(host)
                        if self_verify and hasattr(store, "supports_domain_strict")
                        else store.supports_domain(host)
                    )
                    if supports_domain:
                        found_store = store
                        break
                if found_store is not None:
                    if found_store not in domains_by_store:
                        domains_by_store[found_store] = []
                    domains_by_store[found_store].append(host)
                else:
                    print(f"Warning: No challenge solver found that supports domain: {host}. Skipping.")

            if len(domains_by_store) == 0 and not skip_failing:
                raise ValueError("None of the domains are owned by this machine or could be verified")

            if batch_generator is None:
                issuance_batches = [(store, domains) for store, domains in domains_by_store.items()]
            else:
                wildcard_batches = [
                    (store, [domain])
                    for store, domains in domains_by_store.items()
                    for domain in domains
                    if is_wildcard_domain(domain)
                ]
                concrete_batches = []
                for store, domains in domains_by_store.items():
                    concrete_domains = [domain for domain in domains if not is_wildcard_domain(domain)]
                    if concrete_domains:
                        concrete_batches.extend((store, batch) for batch in batch_generator(concrete_domains))
                issuance_batches = [*wildcard_batches, *concrete_batches]

            issued_domains: List[str] = []
            failures: List[FailedDomains] = []
            first_error: Optional[CertApiException] = None
            for store, planned_batch in issuance_batches:
                batch: List[str] = []
                for domain in planned_batch:
                    domain = normalize_domain(domain)
                    if not domain or domain in batch:
                        continue
                    if any(domain_matches_cert_domain(issued, domain) for issued in issued_domains):
                        continue
                    batch.append(domain)
                if not batch:
                    continue

                try:
                    private_key, fullchain_cert = self.cert_issuer.generate_key_and_cert_for_domains(
                        batch,
                        key_type=key_type,
                        expiry_days=expiry_days,
                        country=country,
                        state=state,
                        locality=locality,
                        organization=organization,
                        user_id=user_id,
                        challenge_solver=store,
                    )
                except CertApiException as error:
                    # Fail fast when the caller wants all-or-nothing, so a doomed run does not
                    # keep burning ACME orders against the rate limit.
                    if not skip_failing:
                        raise
                    failures.append(FailedDomains.from_exception(batch, error))
                    first_error = first_error if first_error is not None else error
                    print(
                        f"ERROR: Failed to issue certificate for domains {batch}"
                        f" [{type(error).__name__} @ {error.step}]: {error.message}"
                    )
                    continue

                if fullchain_cert:
                    key_id = self.key_store.save_key(private_key, batch[0])
                    self.key_store.save_cert(key_id, fullchain_cert, batch)
                    issued_certs_list.append(IssuedCert(key=private_key, cert=fullchain_cert, domains=batch))
                    issued_domains.extend(batch)
                else:
                    print(f"Failed to issue certificate for domains: {batch}")
                    failures.append(
                        FailedDomains(
                            domains=batch, name="IssuanceFailed", message="ACME issuance returned no certificate"
                        )
                    )

            # Nothing at all could be produced, so surface the reason instead of an empty response.
            if failures and not issued_certs_list and not existing:
                if first_error is not None:
                    raise first_error
                raise CertApiException(
                    f"Could not obtain a certificate for any of: {hosts}",
                    {"failed": [failure.to_json() for failure in failures]},
                    "Issue Certificate",
                )

            # self.cert_issuer.challenge_solver = original_challenge_solver # Restore original
            return createExistingResponse(existing, issued_certs_list, failures)

        else:
            return createExistingResponse(existing, [])


def createExistingResponse(
    existing: Dict[str, Tuple[int | str, Key, List[Certificate] | str]],
    issued_certs: List[IssuedCert],
    failed: List[FailedDomains] = None,
):
    certs = []
    certMap = {}

    for h, (id, key, cert) in existing.items():
        if id in certMap:
            certMap[id][0].append(h)
        else:
            if isinstance(cert, str):
                cert_pem = cert
            elif isinstance(cert, list):
                cert_pem = certs_to_pem(cert).decode("utf-8")
            else:
                cert_pem = cert_to_pem(cert).decode("utf-8")

            certMap[id] = (
                [h],
                key,
                cert_pem,
            )

    for hosts, key, cert in certMap.values():
        certs.append(IssuedCert(key=key, cert=cert, domains=hosts))

    return CertificateResponse(existing=certs, issued=issued_certs, failed=failed or [])
