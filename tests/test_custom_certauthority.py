import pytest
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from certapi.crypto.crypto_classes import Key
from certapi.issuers.SelfCertIssuer import CertificateIssuer  # Replace with actual import
from certapi.crypto.crypto import gen_key_ed25519, gen_key_rsa, gen_key_secp256r1


@pytest.mark.parametrize("ca_key_type", ["rsa", "ecdsa", "ed25519"])
@pytest.mark.parametrize("csr_key_type", ["rsa", "ecdsa", "ed25519"])
def test_ca_and_leaf_cert_all_key_pairs(ca_key_type, csr_key_type):
    # Generate CA key and CA instance
    ca_key = Key.generate(ca_key_type)
    ca = CertificateIssuer(
        ca_key,
        country="US",
        state="California",
        locality="Los Angeles",
        organization="TestOrg",
        common_name="testca.local",
    )
    ca_cert = ca.get_ca_cert()

    # Generate leaf/CSR key
    leaf_key = Key.generate(csr_key_type)
    csr = leaf_key.create_csr("example.com")

    # Build subject and CSR
    # subject = ca._build_name({"common_name": "example.com"})
    # csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    # csr = csr_builder.sign(leaf_key, hashes.SHA256())

    # Sign CSR with CA key
    leaf_cert = ca.sign_csr(csr, expiry_days=30)

    # Assertions copied exactly from your original test

    assert isinstance(ca_cert, x509.Certificate)
    assert ca_cert.subject == ca_cert.issuer  # Self-signed
    assert isinstance(ca_cert.not_valid_before, datetime)
    assert isinstance(ca_cert.not_valid_after, datetime)
    assert ca_cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "testca.local"

    assert isinstance(leaf_cert, x509.Certificate)
    assert leaf_cert.not_valid_after > leaf_cert.not_valid_before
    assert leaf_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "example.com"

    # Check issuer consistency
    assert leaf_cert.issuer == ca_cert.subject
