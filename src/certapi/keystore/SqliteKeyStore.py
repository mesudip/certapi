
import os
import sqlite3
from typing import Tuple, Optional, Union, List
from certapi.crypto import Key, Certificate, certs_from_pem, cert_to_pem, certs_to_pem
from .KeyStore import KeyStore

class SqliteKeyStore(KeyStore):
    def __init__(self, db_path="db/database.db"):
        self.db_path = db_path
        self.db = None
        self._initialize_db()

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
        if self.db is None:
            self.db = sqlite3.connect(self.db_path)
        return self.db

    def save_key(self, key: Key, id: str | int | None) -> int | str:
        conn = self._get_db_connection()
        cur = conn.cursor()
        if isinstance(id, int):
            cur.execute("INSERT INTO private_keys (id, content) VALUES (?, ?)", (id, key.to_der()))
        else:
            cur.execute("INSERT INTO private_keys (name, content) VALUES (?, ?)", (id, key.to_der()))
        cur.close()
        conn.commit()
        return cur.lastrowid if isinstance(id, int) else id

    def find_key_by_id(self, id: str | int) -> Optional[Key]:
        conn = self._get_db_connection()
        cur = conn.cursor()
        if isinstance(id, int):
            cur.execute("SELECT content FROM private_keys WHERE id = ?", (id,))
        else:
            cur.execute("SELECT content FROM private_keys WHERE name = ?", (id,))
        res = cur.fetchone()
        cur.close()
        if res:
            return Key.from_der(res[0])
        return None

    def save_cert(
        self, private_key_id: int, cert: Certificate | str | List[Certificate], domains: List[str], name: str = None
    ) -> int:
        conn = self._get_db_connection()
        cur = conn.cursor()

        cert_data = self._get_cert_as_pem_bytes(cert)

        cur.execute(
            "INSERT INTO certificates (name, priv_id, content) VALUES (?, ?, ?)",
            (name, private_key_id, cert_data),
        )
        cert_id = cur.lastrowid

        for domain in domains:
            cur.execute("INSERT INTO ssl_domains (domain, certificate_id) VALUES (?, ?)", (domain, cert_id))
        cur.close()
        conn.commit()
        return cert_id

    def find_cert_by_domain(self, domain: str) -> None | Tuple[int | str, Key, List[Certificate]]:
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

        if res is None:
            return None

        certs = self._get_cert_as_cert_list(res[2])
        return (res[0], Key.from_der(res[1]), certs)

    def get_cert_by_id(self, id: str) -> None | Tuple[int | str, Key, List[Certificate]]:
        conn = self._get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT c.id, p.content, c.content
            FROM certificates c
            JOIN private_keys p ON c.priv_id = p.id
            WHERE c.id = ?
            """,
            (id,),
        )
        res = cur.fetchone()

        cur.close()

        if res is None:
            return None

        certs = self._get_cert_as_cert_list(res[2])
        return (res[0], Key.from_der(res[1]), certs)


    def find_key_by_name(self, id):
        raise NotImplementedError

    def find_key_and_cert_by_domain(self, domain):
        raise NotImplementedError

    def find_key_and_cert_by_cert_id(self, id):
        raise NotImplementedError

