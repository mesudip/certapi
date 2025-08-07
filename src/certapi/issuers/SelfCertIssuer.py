from typing import Optional, List, Union
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from certapi.crypto import Key, RSAKey, ECDSAKey, Ed25519Key
from .abstract_certissuer import CertIssuer


class SelfCertIssuer(CertIssuer):
    def __init__(
        self,
        key: Key,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        common_name: Optional[str] = None,
    ):
        """Initialize the CertificateIssuer with a Key object."""
        self.root_key: Key = key
        self.issuer_fields = {
            "country": country,
            "state": state,
            "locality": locality,
            "organization": organization,
            "common_name": common_name,
        }
        self.issuer = self._build_name(self.issuer_fields)

    def _build_name(self, fields: dict, include_user_id=False, domain=None) -> x509.Name:
        """Build an X509 Name object from field dictionary."""
        name_attrs = []
        field_map = {
            "country": NameOID.COUNTRY_NAME,
            "state": NameOID.STATE_OR_PROVINCE_NAME,
            "locality": NameOID.LOCALITY_NAME,
            "organization": NameOID.ORGANIZATION_NAME,
            "common_name": NameOID.COMMON_NAME,
        }

        for key, oid in field_map.items():
            value = fields.get(key)
            if value:
                name_attrs.append(x509.NameAttribute(oid, value))

        if include_user_id:
            user_id = fields.get("user_id", domain)
            if user_id:
                name_attrs.append(x509.NameAttribute(NameOID.USER_ID, user_id))

        return x509.Name(name_attrs)

    def get_ca_cert(self) -> x509.Certificate:
        """Generate a self-signed CA certificate."""
        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(self.issuer)
            .issuer_name(self.issuer)
            .public_key(self.root_key.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        )
        return self.root_key.sign_csr(builder)

    def sign_csr(
        self,
        csr: x509.CertificateSigningRequest,
        expiry_days: int = 90,
    ) -> x509.Certificate:
        """Sign a CSR and return a certificate signed by this CA."""
        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self.issuer)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=expiry_days))
        )

        for ext in csr.extensions:
            builder = builder.add_extension(ext.value, ext.critical)

        return self.root_key.sign_csr(builder)
