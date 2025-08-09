from abc import ABC, abstractmethod
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from typing import Literal, Optional, List, Union
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import utils

from .crypto import key_to_der, key_to_pem
from certapi.util import b64_string


class Key(ABC):
    key: rsa.RSAPrivateKey | ed25519.Ed25519PrivateKey | ec.EllipticCurvePrivateKey

    @abstractmethod
    def jwk(self):
        pass

    @abstractmethod
    def algorithm_name(self) -> str:
        pass

    @abstractmethod
    def sign(self, message: bytes) -> bytes:
        pass

    def jws_sign(self, message: bytes) -> bytes:
        return self.sign(message)

    @abstractmethod
    def sign_csr(self, csr: x509.CertificateSigningRequestBuilder | x509.CertificateBuilder):
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
    def from_der(der_bytes: bytes, password: str = None):
        key = serialization.load_der_private_key(der_bytes, password)
        if isinstance(key, rsa.RSAPrivateKey):
            return RSAKey(key)
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            return ECDSAKey(key)
        elif isinstance(key, Ed25519PrivateKey):
            return Ed25519Key(key)
        else:
            raise ValueError("Unsupported key type")

    @staticmethod
    def from_pem(pem_str: str, password: str = None):
        key = serialization.load_pem_private_key(pem_str, password)
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

        # Build CSR with optional SAN extension
        csr_builder = x509.CertificateSigningRequestBuilder()
        if domain:
            subject = self._build_name(subject_fields, include_user_id=True, domain=domain)
            csr_builder = csr_builder.subject_name(subject)

        # Always include the domain in SAN, and then add alt_names
        all_alt_names = [domain] + list(alt_names)
        # Remove duplicates while preserving order (CN first, then alt_names order)
        seen = set()
        unique_alt_names = []
        for name in all_alt_names:
            if name not in seen:
                seen.add(name)
                unique_alt_names.append(name)

        csr_builder = csr_builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in unique_alt_names]),
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
        self._jwk = {
            "crv": "Ed25519",
            "kty": "OKP",
            "x": b64_string(public),
        }

    @staticmethod
    def generate():
        key = ed25519.Ed25519PrivateKey.generate()
        return Ed25519Key(key)

    def jwk(self):
        return self._jwk

    def sign(self, message):
        return self.key.sign(message)

    def algorithm_name(self):
        return "EdDSA"

    def sign_csr(self, csr):
        return csr.sign(self.key, None)


class ECDSAKey(Key):
    def __init__(self, key: ec.EllipticCurvePrivateKey):
        self.key = key
        public_key = self.key.public_key()
        public_numbers = public_key.public_numbers()
        self._jwk = {
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
        return self._jwk

    def algorithm_name(self):
        curve_name = self.key.curve.name
        if curve_name == "secp256r1":
            return "ES256"
        elif curve_name == "secp384r1":
            return "ES384"
        elif curve_name == "secp521r1":
            return "ES512"
        else:
            raise ValueError(f"Unsupported EC curve: {curve_name}")

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

    def jws_sign(self, message: bytes) -> bytes:
        print("Jws sign")
        der_sig = self.sign(message)
        r, s = utils.decode_dss_signature(der_sig)
        num_bytes = (self.key.curve.key_size + 7) // 8
        r_bytes = r.to_bytes(num_bytes, "big")
        s_bytes = s.to_bytes(num_bytes, "big")
        return r_bytes + s_bytes

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
