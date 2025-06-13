from abc import ABC, abstractmethod
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec
from cryptography.hazmat.primitives import serialization, hashes, padding
from typing import Literal, Optional, List, Union
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import key_to_der, key_to_pem
from .util import b64_string


class Key(ABC):
    key: rsa.RSAPrivateKey | ed25519.Ed25519PrivateKey | ec.EllipticCurvePrivateKey

    @abstractmethod
    def jwk(self):
        pass

    @abstractmethod
    def sign(self, message):
        pass

    @abstractmethod
    def sign_csr(self, csr):
        pass

    @staticmethod
    def generate(key_type: Literal["rsa", "ecdsa", "ed25519"]) -> "Key":
        if key_type == "rsa":
            return RSAKey.generate()
        elif key_type == "ecdsa":
            return ECDSAKey.generate()
        elif key_type == "ed25519":
            return Ed25519Key.generate()
        else:
            raise ValueError("Unsupported key type. Use 'rsa' or 'ecdsa'")

    @staticmethod
    def from_der(der_bytes):
        key = serialization.load_der_private_key(der_bytes, password=None)
        if isinstance(key, rsa.RSAPrivateKey):
            return RSAKey(key)
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            return ECDSAKey(key)
        elif isinstance(key, Ed25519PrivateKey):
            return Ed25519Key(key)
        else:
            raise ValueError("Unsupported key type")

    @staticmethod
    def from_pem(der_bytes):
        key = serialization.load_pem_private_key(der_bytes, password=None)
        if isinstance(key, rsa.RSAPrivateKey):
            return RSAKey(key)
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            return ECDSAKey(key)
        elif isinstance(key, Ed25519PrivateKey):
            return Ed25519Key(key)
        else:
            raise ValueError("Unsupported key type")

    def to_der(self) -> bytes:
        return key_to_der(self.key)

    def to_pem(self) -> bytes:
        return key_to_pem(self.key)

    def _build_name(self, fields: dict, include_user_id=False, domain=None) -> x509.Name:
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

    def create_csr(
        self,
        domain: str,
        alt_names: List[str] = (),
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> x509.CertificateSigningRequest:
        """
        Create a Certificate Signing Request (CSR) with the specified parameters.

        Args:
            domain: The common name (CN) for the CSR.
            alt_names: List of Subject Alternative Names (SAN) for the CSR.
            country: Country name for the subject.
            state: State or province name for the subject.
            locality: Locality name for the subject.
            organization: Organization name for the subject.
            user_id: Optional user ID to include in the subject.

        Returns:
            x509.CertificateSigningRequest: The generated CSR.
        """
        # Build subject fields
        subject_fields = {
            "country": country,
            "state": state,
            "locality": locality,
            "organization": organization,
            "common_name": domain,
            "user_id": user_id or domain,
        }
        subject = self._build_name(subject_fields, include_user_id=True, domain=domain)

        # Build CSR with optional SAN extension
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
        if alt_names:
            csr_builder = csr_builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(name) for name in alt_names]),
                critical=False,
            )

        # Sign the CSR using the subclass-specific signing method
        return self.sign_csr(csr_builder)


class RSAKey(Key):
    def __init__(self, key: rsa.RSAPrivateKey, hasher=hashes.SHA256()):
        self.key = key
        self.hasher = hasher

    @staticmethod
    def generate():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return RSAKey(key)

    def jwk(self):
        public = self.key.public_key().public_numbers()
        return {
            "e": b64_string((public.e).to_bytes((public.e.bit_length() + 7) // 8, "big")),
            "kty": "RSA",
            "n": b64_string((public.n).to_bytes((public.n.bit_length() + 7) // 8, "big")),
        }

    def sign(self, message):
        return self.key.sign(message, padding.PKCS1v15(), self.hasher)

    def sign_csr(self, csr):
        return csr.sign(self.key, self.hasher)

    def algorithm_name(self):
        return "RS" + str(self.hasher.digest_size * 8)


class Ed25519Key(Key):
    def __init__(self, key: ed25519.Ed25519PrivateKey):
        self.key = key
        self.keyid = "e"
        public = self.key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        self.jwk = {
            "crv": "Ed25519",
            "kty": "OKP",
            "x": b64_string(public),
        }

    @staticmethod
    def generate():
        key = ed25519.Ed25519PrivateKey.generate()
        return Ed25519Key(key)

    def jwk(self):
        return self.jwk

    def sign(self, message):
        return self.key.sign(message)

    def sign_csr(self, csr):
        return csr.sign(self.key, None)


class ECDSAKey(Key):
    def __init__(self, key: ec.EllipticCurvePrivateKey):
        self.key = key
        public_key = self.key.public_key()
        public_numbers = public_key.public_numbers()
        self.jwk = {
            "kty": "EC",
            "crv": self.key.curve.name,
            "x": b64_string(public_numbers.x.to_bytes((public_numbers.x.bit_length() + 7) // 8, "big")),
            "y": b64_string(public_numbers.y.to_bytes((public_numbers.y.bit_length() + 7) // 8, "big")),
        }

    @staticmethod
    def generate():
        key = ec.generate_private_key(ec.SECP256R1())
        return ECDSAKey(key)

    def jwk(self):
        return self.jwk

    def algorithm_name(self):
        return self.key.curve.name

    def sign(self, message):
        key_size = self.key.curve.key_size
        if key_size == 256:
            algorithm = hashes.SHA256()
        elif key_size == 384:
            algorithm = hashes.SHA384()
        elif key_size == 521:
            algorithm = hashes.SHA512()
        else:
            raise ValueError(f"Unsupported curve with key size {key_size}")
        return self.key.sign(message, ec.ECDSA(algorithm))

    def sign_csr(self, csr):
        key_size = self.key.curve.key_size
        if key_size == 256:
            algorithm = hashes.SHA256()
        elif key_size == 384:
            algorithm = hashes.SHA384()
        elif key_size == 521:
            algorithm = hashes.SHA512()
        else:
            raise ValueError(f"Unsupported curve with key size {key_size}")
        return csr.sign(self.key, algorithm)
