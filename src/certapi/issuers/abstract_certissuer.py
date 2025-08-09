from abc import ABC, abstractmethod
from typing import List, Literal, Optional, Union
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from certapi.crypto.crypto import get_csr_hostnames
from certapi.crypto.crypto_classes import ECDSAKey, Ed25519Key, Key, RSAKey
from ..challenge_solver import ChallengeSolver


class CertIssuer(ABC):

    def __init__(self, *args, **kwargs):
        pass

    def setup(self):
        pass

    @abstractmethod
    def sign_csr(
        self,
        csr: x509.CertificateSigningRequest,
        expiry_days: int = 90,
    ) -> x509.Certificate:
        pass

    @staticmethod
    def get_csr_hostnames(csr: x509.CertificateSigningRequest):
        return get_csr_hostnames(csr)

    def generate_key_and_cert_for_domains(
        self,
        hosts: Union[str, List[str]],
        key_type: Literal["rsa", "ecdsa", "ed25519"] = "rsa",
        expiry_days: int = 90,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        user_id: Optional[str] = None,
        challenge_solver: Optional[ChallengeSolver] = None,
    ):
        if len(hosts) == 0:
            raise ValueError("CertIssuer.generate_key_and_cert_for_domains: empty hosts array provided")
        return self.generate_key_and_cert(
            hosts[0],
            hosts[0:],
            key_type,
            expiry_days,
            country,
            state,
            locality,
            organization,
            user_id,
            challenge_solver,
        )

    def generate_key_and_cert_for_domain(
        self,
        host: str,
        key_type: Literal["rsa", "ecdsa", "ed25519"] = "rsa",
        expiry_days: int = 90,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        user_id: Optional[str] = None,
        challenge_solver: Optional[ChallengeSolver] = None,
    ):

        return self.generate_key_and_cert(
            host, [], key_type, expiry_days, country, state, locality, organization, user_id, challenge_solver
        )

    def generate_key_and_cert(
        self,
        domain: str,
        alt_names: List[str] = (),
        key_type: Literal["rsa", "ecdsa", "ed25519"] = "ecdsa",
        expiry_days: int = 90,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        user_id: Optional[str] = None,
        challenge_solver: Optional[ChallengeSolver] = None,
    ) -> tuple:
        """Create a new certificate with a generated key."""
        new_key = Key.generate(key_type)

        # Create CSR using the new key
        csr = new_key.create_csr(
            domain=domain,
            alt_names=alt_names,
            country=country,
            state=state,
            locality=locality,
            organization=organization,
            user_id=user_id or domain,
        )

        # Sign the CSR to get the certificate
        cert = self.sign_csr(csr, expiry_days=expiry_days)

        return new_key, cert
