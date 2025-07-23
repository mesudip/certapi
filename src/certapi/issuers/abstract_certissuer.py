from abc import ABC, abstractmethod
from typing import List, Optional, Union
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import NameOID, ExtensionOID
from certapi.crypto.crypto_classes import ECDSAKey, Ed25519Key, RSAKey

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

    
    def get_csr_hostnames(csr: x509.CertificateSigningRequest):

        domains = []

        common_names = [attr.value for attr in csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
        if common_names:
            cn = common_names[0]
            # Put CN at the beginning, unless it's already in SAN
            if cn not in domains:
                domains.insert(0, cn)

        try:
            san_extension = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san = san_extension.value
            san_domains = san.get_values_for_type(x509.DNSName)
            domains.extend(san_domains)
        except x509.ExtensionNotFound:
            san_domains = []

        seen = set()
        unique_domains = []
        for d in domains:
            if d not in seen:
                seen.add(d)
                unique_domains.append(d)

        return unique_domains



    def generate_key_and_cert_for_domains(self, hosts: Union[str, List[str]],
                                   key_type: str = "rsa",
        expiry_days: int = 90,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        user_id: Optional[str] = None):
        if len(hosts) ==0:
            raise ValueError("CertIssuer.generate_key_and_cert_for_domains: empty hosts array provided")
        return self.generate_key_and_cert(hosts[0],hosts[0:],key_type,expiry_days,country,state,locality,organization,user_id)

    
    def generate_key_and_cert_for_domain(self, host:str,
                                  key_type: str = "rsa",
        expiry_days: int = 90,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        user_id: Optional[str] = None,):

        return self.generate_key_and_cert(host,[],key_type,expiry_days,country,state,locality,organization,user_id)
    

    def generate_key_and_cert(
        self,
        domain: str,
        alt_names: List[str] = (),
        key_type: str = "ecdsa",
        expiry_days: int = 90,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> tuple:
        """Create a new certificate with a generated key."""
        # Generate new key based on key_type
        if key_type == "rsa":
            new_key = RSAKey.generate()
        elif key_type == "ecdsa":
            new_key = ECDSAKey.generate()
        elif key_type == "ed25519":
            new_key = Ed25519Key.generate()
        else:
            raise ValueError("Unsupported key type. Use 'rsa' or 'ecdsa'")

        # Create CSR using the new key
        csr = new_key.create_csr(
            domain=domain,
            alt_names=alt_names,
            country=country or self.issuer_fields.get("country"),
            state=state or self.issuer_fields.get("state"),
            locality=locality or self.issuer_fields.get("locality"),
            organization=organization or self.issuer_fields.get("organization"),
            user_id=user_id or domain,
        )

        # Sign the CSR to get the certificate
        cert = self.sign_csr(csr, expiry_days=expiry_days)

        return new_key, cert

