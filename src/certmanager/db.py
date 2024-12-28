import sqlite3
from typing import Union, Tuple
from .crypto import *
import os
from flask import g
from abc import ABC, abstractmethod

from .crypto_classes import Key


class KeyStore(ABC):
    account_key: RSAPrivateKey

    @abstractmethod
    def save_key(self, key: RSAPrivateKey, name: str = None) -> int | str:
        pass

    @abstractmethod
    def gen_key(self, name: str = None, size: int = 4096) -> RSAPrivateKey:
        pass

    @abstractmethod
    def save_cert(self, private_key_id: int, cert: Certificate, domains: List[str], name: str = None) -> int:
        pass

    @abstractmethod
    def get_cert(self, domain: str) -> None | Tuple[int | str, Key, Certificate]:
        pass


class SqliteKeyStore(KeyStore):
    def __init__(self, db_path="db/database.db"):
        self.db_path = db_path
        self._initialize_db()
        self.account_key = self._init_account_key()

    def _initialize_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS private_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(50) NULL,
                    content BLOB
                );
                CREATE TABLE IF NOT EXISTS certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(50) NULL,
                    priv_id INTEGER REFERENCES private_keys NOT NULL,
                    content BLOB,
                    sign_id INTEGER REFERENCES private_keys NULL
                );
                CREATE TABLE IF NOT EXISTS ssl_domains (
                    domain VARCHAR(255),
                    certificate_id INTEGER REFERENCES certificates
                );
                CREATE TABLE IF NOT EXISTS ssl_wildcards (
                    domain VARCHAR(255),
                    certificate_id INTEGER REFERENCES certificates
                );
                """
            )

    def _get_db_connection(self):
        if "db" not in g:
            g.db = sqlite3.connect(self.db_path)
        return g.db

    def save_key(self, key: RSAPrivateKey, name: str = None) -> int:
        conn = self._get_db_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO private_keys (name, content) VALUES (?, ?)", (name, key_to_der(key)))
        cur.close()
        conn.commit()
        return cur.lastrowid

    def gen_key(self, name: str = None, size: int = 4096) -> RSAPrivateKey:
        key = gen_key_rsa(size)
        self.save_key(key, name)
        return key

    def save_cert(self, private_key_id: int, cert: Certificate, domains: List[str], name: str = None) -> int:
        conn = self._get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO certificates (name, priv_id, content) VALUES (?, ?, ?)",
            (name, private_key_id, cert.public_bytes(serialization.Encoding.DER)),
        )
        cert_id = cur.lastrowid

        for domain in domains:
            cur.execute("INSERT INTO ssl_domains (domain, certificate_id) VALUES (?, ?)", (domain, cert_id))
        cur.close()
        conn.commit()
        return cert_id

    def get_cert(self, domain: str) -> None | Tuple[int | str, Key, Certificate]:
        conn = self._get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT c.id, p.content, c.content
            FROM ssl_domains s
            JOIN certificates c ON s.certificate_id = c.id
            JOIN private_keys p ON c.priv_id = p.id
            WHERE s.domain = ?
            """,
            (domain,),
        )
        res = cur.fetchone()

        cur.close()

        return res if res is None else (res[0], Key.from_der(res[1]), cert_from_der(res[2]))

    def _init_account_key(self) -> RSAPrivateKey:
        acme_key_name = "ACME Account Key"
        conn = sqlite3.connect(self.db_path)
        account_key_data = conn.execute("SELECT content FROM private_keys WHERE name = ?", [acme_key_name]).fetchone()

        if not account_key_data:
            account_key = self.gen_key(acme_key_name)
        else:
            account_key = key_from_der(account_key_data[0])

        print(key_to_pem(account_key).decode("utf-8"))
        conn.close()
        return account_key


class FilesystemKeyStore(KeyStore):
    def __init__(self, base_dir="."):
        self.keys_dir = os.path.join(base_dir, "keys")
        self.certs_dir = os.path.join(base_dir, "certs")
        os.makedirs(self.keys_dir, exist_ok=True)
        os.makedirs(self.certs_dir, exist_ok=True)
        self._init_account_key()

    def _init_account_key(self) -> RSAPrivateKey:
        acme_key_name = "acme_account"
        self.account_key = self.find_key(acme_key_name)
        if self.account_key is None:
            self.account_key = self.gen_key("acme_account")
        return self.account_key

    def save_key(self, key: RSAPrivateKey, name: str = None) -> int:
        key_path = os.path.join(self.keys_dir, f"{name}.key")
        with open(key_path, "wb") as f:
            f.write(key_to_pem(key))
        return name  # Dummy ID since filesystem does not use numeric IDs

    def gen_key(self, name: str = None, size: int = 4096) -> RSAPrivateKey:
        key = gen_key_rsa(size)
        self.save_key(key, name)
        return key

    def find_key(self, name: str) -> Union[None, RSAPrivateKey]:
        key_path = os.path.join(self.keys_dir, f"{name}.key")
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                key_data = f.read()
            return key_from_pem(key_data)
        return None

    def find_cert(self, name: str) -> Union[None, Certificate]:
        cert_path = os.path.join(self.certs_dir, f"{name}.crt")
        if os.path.exists(cert_path):
            with open(cert_path, "rb") as f:
                cert_data = f.read()
            return cert_from_pem(cert_data)
        return None

    def save_cert(self, private_key_id: str, cert: Certificate, domains: list, name: str = None) -> int:
        if name:
            cert_path = os.path.join(self.certs_dir, f"{name}.crt")
            with open(cert_path, "wb") as f:
                f.write(cert_to_pem(cert))
        key_content = None
        key_path = os.path.join(self.keys_dir, f"{private_key_id}.key")
        with open(key_path, "rb") as f:
            key_content = f.read()
        for domain in domains:
            if domain != private_key_id:
                with open(os.path.join(self.keys_dir, f"{domain}.key"), "wb") as f:
                    f.write(key_content)
            domain_cert_path = os.path.join(self.certs_dir, f"{domain}.crt")
            with open(domain_cert_path, "wb") as f:
                f.write(cert_to_pem(cert))

        return name if name else domains[0]  # Dummy ID since filesystem does not use numeric IDs

    def get_cert(self, domain: str) -> None | Tuple[str, Key, Certificate]:
        cert_path = os.path.join(self.certs_dir, f"{domain}.crt")
        key_path = os.path.join(self.keys_dir, f"{domain}.key")
        key = None
        cert = None
        if os.path.exists(key_path):
            try:
                with open(key_path, "rb") as f:
                    key = Key.from_pem(f.read())
            except ValueError:
                pass

        if os.path.exists(cert_path):
            try:
                with open(cert_path, "rb") as f:
                    cert = cert_from_pem(f.read())
            except ValueError:
                pass

        if cert is None or key is None:
            return None
        return (domain, key, cert)
