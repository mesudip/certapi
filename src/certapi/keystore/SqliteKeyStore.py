import os
import sqlite3
from typing import Tuple, Optional, Union, List
from certapi.crypto import Key, Certificate, certs_from_pem, cert_to_pem, certs_to_pem
from certapi.domain_matching import is_wildcard_domain, normalize_domain, wildcard_candidate_for_domain
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

    def save_key(self, key: Key, name: str | int | None) -> int | str:
        conn = self._get_db_connection()
        cur = conn.cursor()
        if name is None:
            cur.execute("INSERT INTO private_keys (content) VALUES (?)", (key.to_der(),))
            conn.commit()
            return cur.lastrowid
        elif isinstance(name, int):
            cur.execute("INSERT INTO private_keys (id, content) VALUES (?, ?)", (name, key.to_der()))
        else:  # isinstance(name, str)
            cur.execute("INSERT INTO private_keys (name, content) VALUES (?, ?)", (name, key.to_der()))
        conn.commit()
        return name

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
        self,
        private_key_id: int | str,
        cert: Certificate | str | List[Certificate],
        domains: List[str],
        name: str = None,
    ) -> int:
        conn = self._get_db_connection()
        cur = conn.cursor()

        # Ensure private_key_id is an integer ID from the private_keys table
        if isinstance(private_key_id, str):
            cur.execute("SELECT id FROM private_keys WHERE name = ?", (private_key_id,))
            result = cur.fetchone()
            if result:
                private_key_id = result[0]
            else:
                raise ValueError(f"Private key with name '{private_key_id}' not found.")

        cert_data = self._get_cert_as_pem_bytes(cert)

        cur.execute(
            "INSERT INTO certificates (name, priv_id, content) VALUES (?, ?, ?)",
            (name, private_key_id, cert_data),
        )
        cert_id = cur.lastrowid

        for domain in domains:
            domain = normalize_domain(domain)
            table = "ssl_wildcards" if is_wildcard_domain(domain) else "ssl_domains"
            cur.execute(f"INSERT INTO {table} (domain, certificate_id) VALUES (?, ?)", (domain, cert_id))
        conn.commit()
        return cert_id

    def find_cert_by_domain(self, domain: str) -> None | Tuple[int | str, Key, List[Certificate]]:
        result = self.find_key_and_cert_by_domain(domain)
        if result is None:
            return None
        return result

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

    def find_key_by_name(self, name: str) -> Optional[Key]:
        conn = self._get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT content FROM private_keys WHERE name = ?", (name,))
        res = cur.fetchone()
        cur.close()
        if res:
            return Key.from_der(res[0])
        return None

    def find_key_and_cert_by_domain(self, domain: str) -> None | Tuple[int | str, Key, List[Certificate]]:
        result = self.find_key_and_cert_covering_domain(domain)
        if result is None:
            return None
        return (result[1], result[2], result[3])

    def find_key_and_cert_covering_domain(self, domain: str) -> None | Tuple[str, int | str, Key, List[Certificate]]:
        domain = normalize_domain(domain)
        if not domain:
            return None

        for table, lookup_domain in self._domain_lookup_order(domain):
            result = self._find_key_and_cert_in_domain_table(table, lookup_domain)
            if result is not None:
                cert_id, key, certs = result
                return (lookup_domain, cert_id, key, certs)
        return None

    def _domain_lookup_order(self, domain: str) -> List[Tuple[str, str]]:
        lookups = [("ssl_domains", domain), ("ssl_wildcards", domain)]
        wildcard_domain = None if is_wildcard_domain(domain) else wildcard_candidate_for_domain(domain)
        if wildcard_domain:
            lookups.extend(
                [
                    ("ssl_wildcards", wildcard_domain),
                    ("ssl_domains", wildcard_domain),
                ]
            )
        return lookups

    def _find_key_and_cert_in_domain_table(
        self, table: str, domain: str
    ) -> None | Tuple[int | str, Key, List[Certificate]]:
        conn = self._get_db_connection()
        cur = conn.cursor()
        cur.execute(
            f"""
            SELECT c.id, p.content, c.content
            FROM {table} s
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

    def find_key_and_cert_by_cert_id(self, id: str) -> None | Tuple[Key, List[Certificate]]:
        conn = self._get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT p.content, c.content
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

        key = Key.from_der(res[0])
        certs = self._get_cert_as_cert_list(res[1])
        return (key, certs)
