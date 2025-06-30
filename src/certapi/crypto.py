from typing import List, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, ed25519
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate, CertificateSigningRequestBuilder, CertificateSigningRequest

from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime

from .util import b64_encode, b64_string

__no_enc = serialization.NoEncryption()


def gen_key_rsa(key_size=4096):
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def gen_key_secp256r1():
    curve = ec.SECP256R1()
    return ec.generate_private_key(curve, default_backend())


def gen_key_ed25519():
    return ed25519.Ed25519PrivateKey.generate()


def gen_key_ecdsa():
    return ec.generate_private_key(ec.SECP256R1())


def get_algorithm_name(key):
    if isinstance(key, RSAPrivateKey):
        return "RS256"
    elif isinstance(key, Ed25519PrivateKey):
        return "EdDSA"
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        curve_name = key.curve.name
        if curve_name == "secp256r1":
            return "ES256"
        elif curve_name == "secp384r1":
            return "ES384"
        elif curve_name == "secp521r1":
            return "ES512"
        else:
            raise ValueError(f"Unsupported EC curve: {curve_name}")
    else:
        raise ValueError("Unsupported key type")


def jwk(key: Union[RSAPrivateKey, Ed25519PrivateKey, EllipticCurvePrivateKey]):
    if isinstance(key, RSAPrivateKey):
        return jwk_rsa(key)
    elif isinstance(key, Ed25519PrivateKey):
        return jwk_ed25519(key)
    elif isinstance(key, EllipticCurvePrivateKey):
        return jwk_secp256r1(key)


def jwk_ed25519(private_key: Ed25519PrivateKey):
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    # Create the JWK for the Ed25519 public key
    return {"crv": "Ed25519", "kty": "OKP", "x": b64_string(public_key_bytes)}


def jwk_secp256r1(key: ec.EllipticCurvePrivateKey):

    numbers = key.public_key().public_numbers()

    # Create a JSON Web Key (JWK) representation of the public key
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64_string(numbers.x.to_bytes(32, "big")),
        "y": b64_string(numbers.y.to_bytes(32, "big")),
    }


def jwk_rsa(account_key: RSAPrivateKey):
    public = account_key.public_key().public_numbers()
    # json web key format for public key
    return {
        "e": b64_string((public.e).to_bytes((public.e.bit_length() + 7) // 8, "big")),
        "kty": "RSA",
        "n": b64_string((public.n).to_bytes((public.n.bit_length() + 7) // 8, "big")),
    }


def key_from_der(bytes):
    return serialization.load_der_private_key(bytes, None)


def key_from_pem(data: bytes):
    return serialization.load_pem_private_key(data, None)


def cert_from_pem(data: bytes) -> Certificate:
    return x509.load_pem_x509_certificate(data)

def certs_from_pem(data: bytes) -> List[Certificate]:
    return x509.load_pem_x509_certificates(data)

def cert_to_der(cert):
    return cert.public_bytes(serialization.Encoding.DER)

def cert_to_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)

def certs_to_pem(certs: List[Certificate]) -> bytes:
    return b"".join([cert_to_pem(cert) for cert in certs])

def cert_from_der(data: bytes) -> Certificate:
    return x509.load_der_x509_certificate(data)


def key_to_pem(key: RSAPrivateKey):
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def csr_to_pem(csr) -> bytes:
    return csr.public_bytes(serialization.Encoding.PEM)


def csr_to_der(csr) -> bytes:
    return csr.public_bytes(serialization.Encoding.DER)


def sign(key: Union[RSAPrivateKey, Ed25519PrivateKey, EllipticCurvePrivateKey], message, hasher=hashes.SHA256()):
    #    return key.sign(message,padding.PSS(mgf=padding.(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
    if isinstance(key, RSAPrivateKey):
        return key.sign(message, padding.PKCS1v15(), hasher)
    elif isinstance(key, Ed25519PrivateKey):
        return key.sign(message)
    elif isinstance(key, EllipticCurvePrivateKey):
        return key.sign(message, ec.ECDSA(hasher))


def sign_for_jws(key, message, hasher=hashes.SHA256()):
    if isinstance(key, EllipticCurvePrivateKey):
        der_sig = key.sign(message, ec.ECDSA(hasher))
        r, s = utils.decode_dss_signature(der_sig)
        num_bytes = (key.curve.key_size + 7) // 8
        r_bytes = r.to_bytes(num_bytes, "big")
        s_bytes = s.to_bytes(num_bytes, "big")
        return r_bytes + s_bytes
    else:
        return sign(key, message, hasher)


def sign_jws(key: RSAPrivateKey, data: object):
    pass


def key_to_der(key: RSAPrivateKey | Ed25519PrivateKey | EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=__no_enc
    )


def create_csr(
    private_key: Union[RSAPrivateKey, Ed25519PrivateKey, EllipticCurvePrivateKey],
    main_domain: str,
    alternatives: List[str] = None,
) -> CertificateSigningRequest:
    subject = x509.Name(
        [
            # Provide various details about who we are.
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Bagmati"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Kathmandu"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sireto Technology"),
            x509.NameAttribute(NameOID.COMMON_NAME, main_domain),
        ]
    )
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    if alternatives is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(alt) for alt in alternatives]), critical=True
        )
    return builder.sign(private_key, hashes.SHA256())


def self_sign():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = create_csr(key, "host4.sireto.dev", []).sign(key, hashes.SHA256())
    with open("test.csr", "wb") as f:
        f.write(csr_to_pem(csr))

    # Various details about who we are. For a self-signed certificate the
    # subject and issuer are always the same.
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, "domain3.sireto.dev"),
        ]
    )
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=10))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
            # Sign our certificate with our private key
        )
        .sign(key, hashes.SHA256())
    )
    # Write our certificate out to disk.

    with open("certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # getting public key from certificate.
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        # Do something RSA specific
        pass
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        # Do something EC specific
        pass
    else:
        # Remember to handle this case
        pass


def digest_sha256(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()
