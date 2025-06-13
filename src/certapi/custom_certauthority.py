from typing import Optional, List, Union
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from certapi.crypto_classes import Key, RSAKey, ECDSAKey, Ed25519Key  # Assuming Key classes are in crypto_keys module


class CertificateIssuer:
    def __init__(
        self,
        key: Key,
        *,
        country: Optional[str] = "NP",
        state: Optional[str] = "Kathmandu",
        locality: Optional[str] = "Buddhanagar",
        organization: Optional[str] = "Sireto Technology",
        common_name: Optional[str] = "sireto.io",
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
            user_id = fields.get("user_id") or domain
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

    def create_key_and_cert(
        self,
        domain: str,
        alt_names: List[str] = (),
        key_type: str = "rsa",
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
