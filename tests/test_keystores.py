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
