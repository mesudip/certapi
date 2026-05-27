from time import timezone
import pytest
import os
import psycopg2  # Added for PostgreSQL database creation
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT  # Added for PostgreSQL database creation

from certapi import Key, Certificate
from certapi.crypto.crypto import cert_to_pem, certs_to_pem
from certapi.keystore import SqliteKeyStore, FileSystemKeyStore, PostgresKeyStore
from typing import List, Tuple, Union
from datetime import UTC, datetime, timedelta
from certapi import KeyStore, Certificate, Key

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta


@pytest.fixture(scope="session")
def ca_key():
    return Key.generate("ecdsa")


@pytest.fixture(params=["sqlite", "filesystem", "postgresql"])
def keystore(request, tmp_path):
    if request.param == "sqlite":
        db_path = tmp_path / "test.db"
        store = SqliteKeyStore(db_path=str(db_path))
        yield store
        # Clean up after test
        if os.path.exists(db_path):
            os.remove(db_path)
    elif request.param == "filesystem":
        base_dir = tmp_path / "keystore_fs"
        store = FileSystemKeyStore(base_dir=str(base_dir))
        yield store
        # Clean up after test
        import shutil

        if os.path.exists(base_dir):
            shutil.rmtree(base_dir)
    elif request.param == "postgresql":
        db_url = "postgresql://localhost/test_db"
        try:
            conn_no_db = psycopg2.connect("postgresql://localhost/postgres")
            conn_no_db.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            cur_no_db = conn_no_db.cursor()
            cur_no_db.execute("SELECT 1 FROM pg_database WHERE datname = 'test_db'")
            exists = cur_no_db.fetchone()
            if not exists:
                cur_no_db.execute("CREATE DATABASE test_db")
            cur_no_db.close()
            conn_no_db.close()
        except psycopg2.OperationalError as e:
            pytest.skip(f"Could not connect to PostgreSQL to create test_db: {e}")

        store = PostgresKeyStore(db_url=db_url)
        yield store
        # Clean up after test: drop tables
        with store.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("DROP TABLE IF EXISTS ssl_wildcards;")
            cur.execute("DROP TABLE IF EXISTS ssl_domains;")
            cur.execute("DROP TABLE IF EXISTS certificates;")
            cur.execute("DROP TABLE IF EXISTS private_keys;")
            conn.commit()
            cur.close()


def test_save_and_find_key(keystore: KeyStore):
    key = Key.generate("rsa")
    key_id = keystore.save_key(key, "test_key")
    assert key_id is not None

    found_key = keystore.find_key_by_name("test_key")
    assert found_key is not None
    assert found_key.to_pem() == key.to_pem()


def test_save_and_find_cert(keystore: KeyStore, ca_key: Key):
    key = Key.generate("rsa")
    key_id = keystore.save_key(key, "cert_key")

    csr = key.create_csr(domain="example.com", alt_names=["example.com"])

    cert = sign_csr(csr, ca_key, 7)

    cert_id = keystore.save_cert(key_id, cert, ["example.com"], "test_cert")
    assert cert_id is not None

    found_cert_tuple = keystore.find_key_and_cert_by_domain("example.com")
    assert found_cert_tuple is not None
    found_id, found_key, found_certs = found_cert_tuple
    if not isinstance(keystore, FileSystemKeyStore):
        assert found_id == cert_id
    assert found_key.to_pem() == key.to_pem()
    assert len(found_certs) == 1
    assert cert_to_pem(found_certs[0]) == cert_to_pem(cert)


def test_get_non_existent_key(keystore: KeyStore):
    found_key = keystore.find_key_by_name("non_existent_key")
    assert found_key is None


def test_get_non_existent_cert(keystore: KeyStore):
    found_cert = keystore.find_key_and_cert_by_domain("nonexistent.com")
    assert found_cert is None


def test_save_key_with_int_id(keystore: KeyStore):
    key = Key.generate("ecdsa")
    key_id = keystore.save_key(key, 123)
    assert key_id == 123 or key_id == "123"

    found_key = keystore.find_key_by_id(123)
    assert found_key is not None
    assert found_key.to_pem() == key.to_pem()


def test_save_cert_with_list_of_certs(keystore, ca_key: Key):
    key = Key.generate("rsa")
    key_id = keystore.save_key(key, "cert_list_key")

    csr1 = key.create_csr(domain="cert1.example.com", alt_names=["cert1.example.com"])
    cert1 = sign_csr(csr1, ca_key, 1)

    csr2 = key.create_csr(domain="cert2.example.com", alt_names=["cert2.example.com"])
    cert2 = sign_csr(csr2, ca_key, 1)

    certs_list = [cert1, cert2]
    cert_id = keystore.save_cert(key_id, certs_list, ["cert1.example.com", "cert2.example.com"], "test_certs_list")
    assert cert_id is not None

    found_cert_tuple = keystore.find_key_and_cert_by_domain("cert1.example.com")
    assert found_cert_tuple is not None
    found_id, found_key, found_certs = found_cert_tuple
    if not isinstance(keystore, FileSystemKeyStore):
        assert found_id == cert_id
    assert found_key.to_pem() == key.to_pem()
    assert len(found_certs) == 2
    assert cert_to_pem(found_certs[0]) == cert_to_pem(cert1)
    assert cert_to_pem(found_certs[1]) == cert_to_pem(cert2)


def test_get_cert_by_id(keystore: KeyStore, ca_key: Key):
    key = Key.generate("rsa")
    domain = "example.com"

    key_id = keystore.save_key(key, domain)

    csr = key.create_csr(domain=domain, alt_names=[domain])
    cert = sign_csr(csr, ca_key, 1)

    cert_id = keystore.save_cert(key_id, cert, [domain], domain)
    assert cert_id is not None

    found_cert_tuple = keystore.find_key_and_cert_by_cert_id(cert_id)
    assert found_cert_tuple is not None
    found_key, found_certs = found_cert_tuple
    assert found_key.to_pem() == key.to_pem()
    assert len(found_certs) == 1
    assert cert_to_pem(found_certs[0]) == cert_to_pem(cert)


@pytest.mark.parametrize("store_type", ["sqlite", "filesystem"])
def test_wildcard_cert_covers_single_label_subdomain(store_type, tmp_path, ca_key: Key):
    if store_type == "sqlite":
        keystore = SqliteKeyStore(db_path=str(tmp_path / "wildcard.db"))
    else:
        keystore = FileSystemKeyStore(base_dir=str(tmp_path / "wildcard_fs"))

    key = Key.generate("rsa")
    key_id = keystore.save_key(key, "*.example.com")
    csr = key.create_csr(domain="*.example.com", alt_names=["*.example.com"])
    cert = sign_csr(csr, ca_key, 7)
    keystore.save_cert(key_id, cert, ["*.example.com"], "*.example.com")

    direct = keystore.find_key_and_cert_by_domain("*.example.com")
    assert direct is not None

    covered = keystore.find_key_and_cert_covering_domain("api.example.com")
    assert covered is not None
    matched_domain, found_id, found_key, found_certs = covered
    assert matched_domain == "*.example.com"
    assert found_key.to_pem() == key.to_pem()
    assert cert_to_pem(found_certs[0]) == cert_to_pem(cert)

    by_domain = keystore.find_key_and_cert_by_domain("api.example.com")
    assert by_domain is not None
    assert by_domain[1].to_pem() == key.to_pem()
    assert keystore.find_key_and_cert_by_domain("example.com") is None
    assert keystore.find_key_and_cert_by_domain("example.co.uk") is None
    assert keystore.find_key_and_cert_by_domain("v1.api.example.com") is None


@pytest.mark.parametrize("store_type", ["sqlite", "filesystem"])
def test_exact_cert_takes_precedence_over_wildcard_cert(store_type, tmp_path, ca_key: Key):
    if store_type == "sqlite":
        keystore = SqliteKeyStore(db_path=str(tmp_path / "precedence.db"))
    else:
        keystore = FileSystemKeyStore(base_dir=str(tmp_path / "precedence_fs"))

    wildcard_key = Key.generate("rsa")
    wildcard_key_id = keystore.save_key(wildcard_key, "*.example.com")
    wildcard_csr = wildcard_key.create_csr(domain="*.example.com", alt_names=["*.example.com"])
    wildcard_cert = sign_csr(wildcard_csr, ca_key, 7)
    keystore.save_cert(wildcard_key_id, wildcard_cert, ["*.example.com"], "*.example.com")

    exact_key = Key.generate("rsa")
    exact_key_id = keystore.save_key(exact_key, "api.example.com")
    exact_csr = exact_key.create_csr(domain="api.example.com", alt_names=["api.example.com"])
    exact_cert = sign_csr(exact_csr, ca_key, 7)
    keystore.save_cert(exact_key_id, exact_cert, ["api.example.com"], "api.example.com")

    covered = keystore.find_key_and_cert_covering_domain("api.example.com")
    assert covered is not None
    matched_domain, found_id, found_key, found_certs = covered
    assert matched_domain == "api.example.com"
    assert found_key.to_pem() == exact_key.to_pem()
    assert cert_to_pem(found_certs[0]) == cert_to_pem(exact_cert)


def test_sqlite_wildcard_save_uses_wildcard_table(tmp_path, ca_key: Key):
    db_path = tmp_path / "wildcard-table.db"
    keystore = SqliteKeyStore(db_path=str(db_path))

    key = Key.generate("rsa")
    key_id = keystore.save_key(key, "*.example.com")
    csr = key.create_csr(domain="*.example.com", alt_names=["*.example.com"])
    cert = sign_csr(csr, ca_key, 7)
    cert_id = keystore.save_cert(key_id, cert, ["*.example.com"], "*.example.com")

    conn = keystore._get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT certificate_id FROM ssl_wildcards WHERE domain = ?", ("*.example.com",))
    assert cur.fetchone() == (cert_id,)
    cur.execute("SELECT certificate_id FROM ssl_domains WHERE domain = ?", ("*.example.com",))
    assert cur.fetchone() is None
    cur.close()


def test_sqlite_lookup_supports_legacy_wildcard_rows(tmp_path, ca_key: Key):
    keystore = SqliteKeyStore(db_path=str(tmp_path / "legacy-wildcard.db"))

    key = Key.generate("rsa")
    key_id = keystore.save_key(key, "*.example.com")
    csr = key.create_csr(domain="*.example.com", alt_names=["*.example.com"])
    cert = sign_csr(csr, ca_key, 7)
    cert_id = keystore.save_cert(key_id, cert, [], "*.example.com")

    conn = keystore._get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO ssl_domains (domain, certificate_id) VALUES (?, ?)", ("*.example.com", cert_id))
    conn.commit()
    cur.close()

    covered = keystore.find_key_and_cert_covering_domain("api.example.com")
    assert covered is not None
    assert covered[0] == "*.example.com"
    assert covered[2].to_pem() == key.to_pem()


def sign_csr(csr: x509.CertificateSigningRequest, issuer_key: Key, days_valid=365) -> Certificate:
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "certapi.pytest.com")]))
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days_valid))
    )

    # Optionally copy extensions from CSR
    for ext in csr.extensions:
        builder = builder.add_extension(ext.value, ext.critical)
    return issuer_key.sign_csr(builder)
