import json
import time
from datetime import datetime, timedelta
from typing import Union, Callable, List

import requests
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate
from requests import Response

from . import Acme
from . import db
from . import crypto
from . import challenge
from .crypto import csr_to_pem, create_csr, gen_key_secp256r1
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, ed25519, dsa


# pathlib.Path.mkdir("/var/www/html/.acme/well-known")


class CustomCertAuthority:
    def __init__(self, key: Union[RSAPrivateKey, DSAPrivateKey, ec.EllipticCurvePrivateKey]):
        self.root_key = key
        self.issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Kathmandu"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Buddhanagar"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sireto Technology"),
                x509.NameAttribute(NameOID.COMMON_NAME, "sireto.io"),
            ]
        )

    def get_ca_cert(self):

        # Assuming self.root_key is the CA private key
        cert = (
            x509.CertificateBuilder()
            .subject_name(self.issuer)
            .issuer_name(self.issuer)
            .public_key(self.root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self.root_key, hashes.SHA256())
        )

        return cert

    # Assuming CustomCertAuthority is your class

    def create_cert(self, domain: str, alt_names: List[str] = (), key_type: str = "rsa", expiry_days=90):
        if key_type == "rsa":
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        elif key_type == "dsa":
            key = dsa.generate_private_key(key_size=2048)
        elif key_type == "ecdsa":
            key = gen_key_secp256r1()
        else:
            raise ValueError("Unsupported key type")

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Kathmandu"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Buddhanagar"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sireto Technology"),
                x509.NameAttribute(NameOID.USER_ID, domain),
            ]
        )

        now = datetime.utcnow()
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=expiry_days))
        )

        for alt_name in alt_names:
            cert_builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(alt_name)]), critical=False)

        cert = cert_builder.sign(self.root_key, hashes.SHA256())

        return (key, cert)
