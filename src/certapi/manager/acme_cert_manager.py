import time
from typing import List, Literal, Optional, Tuple, Union, Dict

from certapi import crypto
from ..acme import Challenge
from ..challenge_store import ChallengeStore

from ..issuers import AcmeCertIssuer,CertIssuer
from ..http.types import CertificateResponse, IssuedCert
from ..keystore.KeyStore import KeyStore
from cryptography.x509 import Certificate,CertificateSigningRequest
from ..crypto import Key,certs_to_pem, cert_to_pem,get_csr_hostnames


class AcmeCertManager():
    def __init__(
        self,
        key_store: KeyStore,
        cert_issuer: AcmeCertIssuer,
        challenge_stores: List[ChallengeStore] = [],
    ):
        self.key_store: KeyStore = key_store
        self.cert_issuer : AcmeCertIssuer = cert_issuer
        self.challenge_stores : List[ChallengeStore]= challenge_stores
        print(f"AcmeCertManager initialized with challenge_stores: {self.challenge_stores}")

    def setup(self):
        self.cert_issuer.setup()
    
    def issue_certificate_for_csr(self, csr: CertificateSigningRequest)->str:
        """
        Returns Certificate
        """
        hostnames = get_csr_hostnames(csr)
        if not hostnames:
            raise ValueError("CSR does not contain any hostnames.")

        # Find a challenge store that supports all hostnames in the CSR
        selected_challenge_store = None
        for store in self.challenge_stores:
            if all(store.supports_domain(h) for h in hostnames):
                selected_challenge_store = store
                break

        if selected_challenge_store is None:
            raise ValueError(f"No challenge store found that supports all domains: {hostnames}")

        fullchain_cert = self.cert_issuer.sign_csr(csr, challenge_store=selected_challenge_store)
        if fullchain_cert:
            # Assuming the private key associated with the CSR is not managed by CertManager directly
            # and is handled by the caller or the cert_issuer's internal process.
            # For now, we'll just return the certificate.
            # If key saving is required here, the private key would need to be passed along with the CSR.
            return fullchain_cert
        else:
            return None

    def issue_certificate(self, hosts: Union[str, List[str]],
                            key_type: Literal["rsa", "ecdsa", "ed25519"] = "rsa",
                            expiry_days: int = 90,
                            country: Optional[str] = None,
                            state: Optional[str] = None,
                            locality: Optional[str] = None,
                            organization: Optional[str] = None,
                            user_id: Optional[str] = None) -> CertificateResponse:
         
        if type(hosts) == str:
            hosts = [hosts]
        
        existing :  Dict[str, Tuple[int | str, Key, List[Certificate] | str]]= {}
        for h in hosts:
            result = self.key_store.find_key_and_cert_by_domain(h)
            if result is not None:
                # result is (domain_id, key, cert_list)
                existing[h] = result # Store the certificate list
        
        missing = [h for h in hosts if h not in existing]
        if len(missing) > 0:
            issued_certs_list = []
            # Group missing hosts by the challenge store that supports them
            domains_by_store: Dict[ChallengeStore, List[str]] = {}
            for host in missing:
                found_store = None
                for store in self.challenge_stores:
                    print(f"Debug: Checking store {store} for domain {host}. supports_domain: {store.supports_domain(host)}")
                    if store.supports_domain(host):
                        print(f"Supports domain: '{host}'",)
                        found_store = store
                        break
                if found_store is not None:
                    if found_store not in domains_by_store:
                        domains_by_store[found_store] = []
                    domains_by_store[found_store].append(host)
                else:
                    print(f"Debug: Current challenge_stores: {self.challenge_stores}")
                    print(f"Warning: No challenge store found that supports domain: {host}. Skipping.")

            # original_challenge_store = self.cert_issuer.challenge_store # Store original

            for store, domains_to_issue in domains_by_store.items():
                
                private_key, fullchain_cert = self.cert_issuer.generate_key_and_cert_for_domains(
                    domains_to_issue,
                    key_type=key_type,
                    expiry_days=expiry_days,
                    country=country,
                    state=state,
                    locality=locality,
                    organization=organization,
                    user_id=user_id,
                    challenge_store=store
                    
                )
                
                if fullchain_cert:
                    key_id = self.key_store.save_key(private_key, domains_to_issue[0])
                    self.key_store.save_cert(key_id, fullchain_cert, domains_to_issue)
                    issued_certs_list.append(IssuedCert(key=private_key, cert=fullchain_cert, domains=domains_to_issue))
                else:
                    print(f"Failed to issue certificate for domains: {domains_to_issue}")
            
            # self.cert_issuer.challenge_store = original_challenge_store # Restore original
            return createExistingResponse(existing, issued_certs_list)
            
        else:
            return createExistingResponse(existing, [])


def createExistingResponse(
    existing: Dict[str, Tuple[int | str, Key, List[Certificate] | str]], issued_certs: List[IssuedCert]
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

    return CertificateResponse(existing=certs, issued=issued_certs)
