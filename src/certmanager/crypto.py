from typing import List

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate

from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime

__no_enc = serialization.NoEncryption()


def gen_key(key_size=4096):
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def key_der_to_pem(bytes) -> bytes:
    k = serialization.load_der_private_key(bytes, None)
    return key_to_pem(k)


def key_from_der(bytes):
    return serialization.load_der_private_key(bytes, None)


def key_from_pem(string):
    return serialization.load_pem_private_key(string, None)


def cert_der_to_pem(bytes) -> bytes:
    return cert_from_der(bytes).public_bytes(serialization.Encoding.PEM)


def cert_from_pem(string: str) -> Certificate:
    return x509.load_pem_x509_certificate()


def cert_from_der(data: bytes) -> Certificate:
    return x509.load_der_x509_certificate(data)


def key_to_pem(key: RSAPrivateKey):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                             __no_enc)


def csr_to_pem(csr) -> bytes:
    return csr.public_bytes(serialization.Encoding.PEM)


def csr_to_der(csr) -> bytes:
    return csr.public_bytes(serialization.Encoding.DER)


def sign(key: RSAPrivateKey, message):
    #    return key.sign(message,padding.PSS(mgf=padding.(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
    return key.sign(message, padding.PKCS1v15(), hashes.SHA256())


def sign_jws(key: RSAPrivateKey, data: object):
    pass


def key_to_der(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=__no_enc)


def create_csr(private_key: RSAPrivateKey, main_domain: str, alternatives: List[str]):
    # Generate a CSR
    return x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, main_domain),
    ])).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(alt) for alt in alternatives
                                     # Describe what sites we want this certificate for.
                                     # x509.DNSName(u"mysite.com"),
                                     # x509.DNSName(u"www.mysite.com"),
                                     # x509.DNSName(u"subdomain.mysite.com"),
                                     ]),
        critical=False, ).sign(private_key, hashes.SHA256())


key = rsa.generate_private_key(public_exponent=65537, key_size=2048)


csr=create_csr(key, "host4.sireto.dev",[])
with open("test.csr", "wb") as f:
    f.write(csr_to_pem(csr))

# Various details about who we are. For a self-signed certificate the
# subject and issuer are always the same.
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"domain3.sireto.dev"),
])
now = datetime.datetime.utcnow()
cert = x509.CertificateBuilder().subject_name(subject) \
    .issuer_name(issuer) \
    .public_key(key.public_key()) \
    .serial_number(x509.random_serial_number()) \
    .not_valid_before(now) \
    .not_valid_after(now + datetime.timedelta(days=10)) \
    .add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]), critical=False,
                   # Sign our certificate with our private key
                   ).sign(key, hashes.SHA256())
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
