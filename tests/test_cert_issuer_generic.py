import pytest
from datetime import UTC, datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from certapi import Key, SelfCertIssuer, Certificate, CertificateSigningRequest, CertificateSigningRequestBuilder
from certapi.issuers.abstract_certissuer import CertIssuer


@pytest.fixture(scope="module")
def self_cert_issuer_instance():
    """Fixture to provide a SelfCertIssuer instance for testing."""
    ca_key = Key.generate("rsa")
    issuer = SelfCertIssuer(
        ca_key,
        country="US",
        state="California",
        locality="Los Angeles",
        organization="TestOrg",
        common_name="testca.local",
    )
    return issuer


@pytest.mark.parametrize("key_type", ["rsa", "ecdsa", "ed25519"])
def test_generate_key_and_cert(self_cert_issuer_instance: SelfCertIssuer, key_type: str):
    """
    Test the generate_key_and_cert method of CertIssuer using SelfCertIssuer.
    """
    domain = "example.com"
    alt_names = ["www.example.com", "mail.example.com"]
    expiry_days = 30

    new_key, cert = self_cert_issuer_instance.generate_key_and_cert(
        domain=domain,
        alt_names=alt_names,
        key_type=key_type,
        expiry_days=expiry_days,
    )

    assert isinstance(new_key, Key)
    assert isinstance(cert, x509.Certificate)

    # Verify subject and issuer
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == domain
    assert cert.issuer == self_cert_issuer_instance.issuer

    # Verify SAN extension
    san_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    san_values = san_extension.value.get_values_for_type(x509.DNSName)
    expected_sans = [domain] + alt_names
    # The domain is now always included in SAN by create_csr, so ensure it's unique and first
    unique_expected_sans = []
    seen = set()
    for name in expected_sans:
        if name not in seen:
            seen.add(name)
            unique_expected_sans.append(name)
    assert set(san_values) == set(unique_expected_sans)

    # Verify expiry
    now_utc = datetime.now(UTC)
    # Ensure certificate validity dates are timezone-aware UTC for comparison
    cert_not_valid_before_utc = cert.not_valid_before_utc.astimezone(timezone.utc)
    cert_not_valid_after_utc = cert.not_valid_after_utc.astimezone(timezone.utc)

    assert cert_not_valid_before_utc <= now_utc
    assert cert_not_valid_after_utc >= now_utc + timedelta(days=expiry_days - 1)  # Allow for slight time difference


@pytest.mark.parametrize("key_type", ["rsa", "ecdsa", "ed25519"])
def test_generate_key_and_cert_no_alt_names(self_cert_issuer_instance: SelfCertIssuer, key_type: str):
    """
    Test generate_key_and_cert with no alt_names provided.
    """
    domain = "no-alt-names.example.com"
    new_key, cert = self_cert_issuer_instance.generate_key_and_cert(
        domain=domain,
        alt_names=[],
        key_type=key_type,
    )
    assert isinstance(new_key, Key)
    assert isinstance(cert, x509.Certificate)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == domain
    san_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    san_values = san_extension.value.get_values_for_type(x509.DNSName)
    assert set(san_values) == {domain}


@pytest.mark.parametrize("key_type", ["rsa", "ecdsa", "ed25519"])
def test_generate_key_and_cert_with_custom_fields(self_cert_issuer_instance: SelfCertIssuer, key_type: str):
    """
    Test generate_key_and_cert with custom country, state, locality, organization, and user_id.
    """
    domain = "custom.example.com"
    country = "CA"
    state = "Ontario"
    locality = "Toronto"
    organization = "CustomOrg"
    user_id = "custom_user_id"

    new_key, cert = self_cert_issuer_instance.generate_key_and_cert(
        domain=domain,
        key_type=key_type,
        country=country,
        state=state,
        locality=locality,
        organization=organization,
        user_id=user_id,
    )

    assert isinstance(new_key, Key)
    assert isinstance(cert, x509.Certificate)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == domain
    assert cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == country
    assert cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value == state
    assert cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value == locality
    assert cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == organization
    assert cert.subject.get_attributes_for_oid(NameOID.USER_ID)[0].value == user_id


@pytest.mark.parametrize("key_type", ["rsa", "ecdsa", "ed25519"])
def test_generate_key_and_cert_for_domain(self_cert_issuer_instance: SelfCertIssuer, key_type: str):
    """
    Test the generate_key_and_cert_for_domain method.
    """
    domain = "single.example.com"
    new_key, cert = self_cert_issuer_instance.generate_key_and_cert_for_domain(
        host=domain,
        key_type=key_type,
    )

    assert isinstance(new_key, Key)
    assert isinstance(cert, x509.Certificate)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == domain
    san_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    san_values = san_extension.value.get_values_for_type(x509.DNSName)
    assert set(san_values) == {domain}  # Now domain should always be in SAN


@pytest.mark.parametrize("key_type", ["rsa", "ecdsa", "ed25519"])
def test_generate_key_and_cert_for_domains(self_cert_issuer_instance: SelfCertIssuer, key_type: str):
    """
    Test the generate_key_and_cert_for_domains method.
    """
    hosts = ["multi.example.com", "sub.multi.example.com"]
    new_key, cert = self_cert_issuer_instance.generate_key_and_cert_for_domains(
        hosts=hosts,
        key_type=key_type,
    )

    assert isinstance(new_key, Key)
    assert isinstance(cert, x509.Certificate)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == hosts[0]
    san_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    san_values = san_extension.value.get_values_for_type(x509.DNSName)
    assert set(san_values) == set(hosts)


def test_generate_key_and_cert_for_domains_empty_hosts(self_cert_issuer_instance: SelfCertIssuer):
    """
    Test generate_key_and_cert_for_domains with an empty hosts list.
    """
    with pytest.raises(ValueError, match="empty hosts array provided"):
        self_cert_issuer_instance.generate_key_and_cert_for_domains(hosts=[])


def test_generate_key_and_cert_unsupported_key_type(self_cert_issuer_instance: SelfCertIssuer):
    """
    Test generate_key_and_cert with an unsupported key type.
    """
    with pytest.raises(ValueError, match="Unsupported key type. Use 'rsa' or 'ecdsa'"):
        self_cert_issuer_instance.generate_key_and_cert(
            domain="invalid.example.com",
            key_type="unsupported",  # type: ignore
        )


def test_get_csr_hostnames():
    """
    Test the static method get_csr_hostnames.
    """
    # Case 1: CSR with CN and SAN
    key = Key.generate("rsa")
    csr = key.create_csr(domain="cn.test.com", alt_names=["san1.test.com", "san2.test.com"])
    hostnames = CertIssuer.get_csr_hostnames(csr)
    assert set(hostnames) == {"cn.test.com", "san1.test.com", "san2.test.com"}
    assert hostnames[0] == "cn.test.com"  # CN should be first if not already in SAN

    # Case 2: CSR with only CN (and it will be added to SAN by create_csr)
    key_cn_only = Key.generate("ecdsa")
    csr_cn_only = key_cn_only.create_csr(domain="onlycn.test.com")
    hostnames_cn_only = CertIssuer.get_csr_hostnames(csr_cn_only)
    assert hostnames_cn_only == ["onlycn.test.com"]

    # Case 3: CN is also in SAN (handled by unique_alt_names logic in create_csr)
    key_cn_in_san = Key.generate("ecdsa")
    csr_cn_in_san = key_cn_in_san.create_csr(
        domain="duplicate.test.com", alt_names=["duplicate.test.com", "another.test.com"]
    )
    hostnames_cn_in_san = CertIssuer.get_csr_hostnames(csr_cn_in_san)
    assert set(hostnames_cn_in_san) == {"duplicate.test.com", "another.test.com"}
    assert hostnames_cn_in_san[0] == "duplicate.test.com"  # CN should still be first and unique
