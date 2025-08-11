import pytest
from datetime import datetime
from cryptography import x509
from certapi import Key, SelfCertIssuer


@pytest.mark.parametrize("ca_key_type", ["rsa", "ecdsa", "ed25519"])
@pytest.mark.parametrize("csr_key_type", ["rsa", "ecdsa", "ed25519"])
def test_ca_and_leaf_cert_all_key_pairs(ca_key_type, csr_key_type):
    # Generate CA key and CA instance
    ca_key = Key.generate(ca_key_type)
    ca: SelfCertIssuer = SelfCertIssuer(
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

    # Sign CSR with CA key
    leaf_cert = ca.sign_csr(csr, expiry_days=30)

    # Assertions
    assert isinstance(ca_cert, x509.Certificate)
    assert ca_cert.subject == ca_cert.issuer  # Self-signed
    assert isinstance(ca_cert.not_valid_before_utc, datetime)
    assert isinstance(ca_cert.not_valid_after_utc, datetime)
    assert ca_cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "testca.local"

    assert isinstance(leaf_cert, x509.Certificate)
    assert leaf_cert.not_valid_after_utc > leaf_cert.not_valid_before_utc
    assert leaf_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "example.com"

    # Check issuer consistency
    assert leaf_cert.issuer == ca_cert.subject
