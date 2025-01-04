from abc import ABC, abstractmethod
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec
from cryptography.hazmat.primitives import serialization, hashes, hmac, padding
from typing import Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import key_to_der, key_to_pem
from .util import b64_string


class Key(ABC):
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


class RSAKey(Key):
    def __init__(self, key: rsa.RSAPrivateKey, hasher=hashes.SHA256()):
        self.key = key
        self.hasher = hasher

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

    def jwk(self):
        return self.jwk

    def sign(self, message):
        return self.key.sign(message)

    def sign_csr(self, csr):
        return csr.sign(self.key, hashes.SHA256())


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
        return csr.sign(self.key, hashes.SHA256())
