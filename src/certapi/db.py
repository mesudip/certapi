import os
import sqlite3
from typing import Tuple, Optional
from contextlib import contextmanager

from .crypto import *
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
    def save_cert(self, private_key_id: int, cert: Certificate|str | List[Certificate] , domains: List[str], name: str = None) -> int:
        pass

    @abstractmethod
    def get_cert(self, domain: str) -> None | Tuple[int | str, Key, Certificate | List[Certificate]]:
        pass


class SqliteKeyStore(KeyStore):
    def __init__(self, db_path="db/database.db"):
        self.db_path = db_path
        self.db = None
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
        if self.db:
            return self.db
        target = self
        try:
            from flask import g

            target = g
        except:
            pass
        if "db" not in target or target.db is None:
            target.db = sqlite3.connect(self.db_path)
        return target.db

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

    def save_cert(self, private_key_id: int, cert: Certificate|str | List[Certificate], domains: List[str], name: str = None) -> int:
        conn = self._get_db_connection()
        cur = conn.cursor()
        
        if isinstance(cert, list):
            cert_data = certs_to_pem(cert)
        elif isinstance(cert, str):
            cert_data = cert.encode()
        else:
            cert_data = cert_to_pem(cert)

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

    def get_cert(self, domain: str) -> None | Tuple[int | str, Key, List[Certificate]]:
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
        
        certs = certs_from_pem(res[2])
        return (res[0], Key.from_der(res[1]), certs)

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
    def __init__(self, base_dir=".", keys_dir_name="keys", certs_dir_name="certs"):
        self.keys_dir = os.path.join(base_dir, keys_dir_name)
        self.certs_dir = os.path.join(base_dir, certs_dir_name)
        os.makedirs(self.keys_dir, exist_ok=True)
        os.makedirs(self.certs_dir, exist_ok=True)
        self._init_account_key()

    def _init_account_key(self) -> RSAPrivateKey:
        acme_key_name = "acme_account"
        self.account_key = self.find_key(acme_key_name)
        if self.account_key is None:
            self.account_key = self.gen_key("acme_account")
        return self.account_key

    def save_key(self, key: RSAPrivateKey, name: str = None) -> str:
        key_path = os.path.join(self.keys_dir, f"{name}.key")
        with open(key_path, "wb") as f:
            f.write(key_to_pem(key))
        return name  # Dummy ID since filesystem does not use numeric IDs

    def gen_key(self, name: str = None, size: int = 4096) -> RSAPrivateKey:
        key = gen_key_secp256r1()
        self.save_key(key, name)
        return key

    def find_key(self, name: str) -> Union[None, RSAPrivateKey]:
        key_path = os.path.join(self.keys_dir, f"{name}.key")
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                key_data = f.read()
            return key_from_pem(key_data)
        return None

    def find_cert(self, name: str) -> Union[None, List[Certificate]]:
        cert_path = os.path.join(self.certs_dir, f"{name}.crt")
        if os.path.exists(cert_path):
            with open(cert_path, "rb") as f:
                cert_data = f.read()
            return certs_from_pem(cert_data)
        return None


    def save_cert(self, private_key_id: str, cert: Certificate | str | List[Certificate], domains: list, name: str = None) -> int:
        if isinstance(cert, list):
            cert_pem = certs_to_pem(cert)
        elif isinstance(cert, str):
            cert_pem = cert.encode()
        else:
            cert_pem = cert_to_pem(cert)

        if name:
            cert_path = os.path.join(self.certs_dir, f"{name}.crt")
            with open(cert_path, "wb") as f:
                f.write(cert_pem)

        key_content = None
        key_path = os.path.join(self.keys_dir, f"{private_key_id}.key")
        with open(key_path, "rb") as f:
            key_content = f.read()

        for domain in domains:
            domain_name = domain
            if name is not None and name.endswith(".selfsigned"):
                domain_name += ".selfsigned"

            if domain_name != private_key_id:
                with open(os.path.join(self.keys_dir, f"{domain_name}.key"), "wb") as f:
                    f.write(key_content)

            domain_cert_path = os.path.join(self.certs_dir, f"{domain_name}.crt")
            with open(domain_cert_path, "wb") as f:
                f.write(cert_pem)


        return name if name else domains[0]  # Dummy ID since filesystem does not use numeric IDs

    def get_cert(self, name: str) -> None | Tuple[str, Key, List[Certificate]]:
        cert_path = os.path.join(self.certs_dir, f"{name}.crt")
        key_path = os.path.join(self.keys_dir, f"{name}.key")
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
                    cert = certs_from_pem(f.read())
            except ValueError:
                pass

        if cert is None or key is None:
            return None
        return (name, key, cert)


class PostgresKeyStore(KeyStore):
    def __init__(self, db_url="postgresql://user:password@localhost/dbname"):
        self.db_url = db_url
        import psycopg2

        self.psycopg2 = psycopg2

    def setup(self):
        self._initialize_pool()
        self._initialize_db()
        self.account_key = self._init_account_key()

    def _initialize_pool(self):
        """Initialize the connection pool."""
        from psycopg2.pool import SimpleConnectionPool

        self.pool = SimpleConnectionPool(1, 10, self.db_url)

    def _check_connection(self, conn):
        """Check if the connection is alive by using the `ping` method."""
        try:
            conn.ping()  # This will raise an exception if the connection is not alive.
            return True
        except self.psycopg2.OperationalError:
            return False

    @contextmanager
    def get_connection(self):
        """Context manager for acquiring and releasing a database connection."""
        conn = self.pool.getconn()

        try:
            # Check connection health
            if not self._check_connection(conn):
                print("Connection is not healthy, reconnecting...")
                self.pool.putconn(conn, close=True)  # Close the bad connection
                conn = self.pool.getconn()  # Get a fresh connection

            # Yield the connection to the caller
            yield conn
        finally:
            # Return the connection to the pool
            self.pool.putconn(conn)

    def _initialize_db(self):
        """Initializes the database with necessary tables."""
        with self.get_connection() as conn:
            # Use the connection directly to execute the query
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS private_keys (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(50) NULL,
                    content BYTEA
                );
                CREATE TABLE IF NOT EXISTS certificates (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(50) NULL,
                    priv_id INTEGER REFERENCES private_keys NOT NULL,
                    content BYTEA,
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
            # No need to explicitly commit here

    def save_key(self, key: RSAPrivateKey, name: str = None) -> int:
        """Saves a private key in the database."""
        with self.get_connection() as conn:
            # Execute the insert directly
            conn.execute(
                "INSERT INTO private_keys (name, content) VALUES (%s, %s) RETURNING id", (name, key_to_der(key))
            )
            key_id = conn.fetchone()[0]  # Fetch the inserted ID
        return key_id

    def gen_key(self, name: str = None, size: int = 4096) -> RSAPrivateKey:
        """Generates a new RSA private key and saves it."""
        key = gen_key_rsa(size)
        self.save_key(key, name)
        return key

    def save_cert(self, private_key_id: int, cert: Certificate | str | List[Certificate], domains: List[str], name: str = None) -> int:
        """Saves a certificate along with associated domains."""
        with self.get_connection() as conn:
            if isinstance(cert, list):
                cert_data = certs_to_pem(cert)
            elif isinstance(cert, str):
                cert_data = cert.encode()
            else:
                cert_data = cert_to_pem(cert)

            # Insert certificate and associated domains directly
            conn.execute(
                "INSERT INTO certificates (name, priv_id, content) VALUES (%s, %s, %s) RETURNING id",
                (name, private_key_id, cert_data),
            )
            cert_id = conn.fetchone()[0]

            # Insert associated domains
            for domain in domains:
                conn.execute("INSERT INTO ssl_domains (domain, certificate_id) VALUES (%s, %s)", (domain, cert_id))

        return cert_id

    def get_cert(self, domain: str) -> Optional[Tuple[int, RSAPrivateKey, List[Certificate]]]:
        """Fetches a certificate and its associated private key for a domain."""
        with self.get_connection() as conn:
            # Directly execute and fetch result
            conn.execute(
                """
                SELECT c.id, p.content, c.content
                FROM ssl_domains s
                JOIN certificates c ON s.certificate_id = c.id
                JOIN private_keys p ON c.priv_id = p.id
                WHERE s.domain = %s
            """,
                (domain,),
            )
            res = conn.fetchone()

            if res:
                return (res[0], Key.from_der(res[1]), certs_from_pem(res[2]))
        return None

    def _init_account_key(self) -> RSAPrivateKey:
        """Initializes or retrieves the ACME account key."""
        acme_key_name = "ACME Account Key"
        with self.get_connection() as conn:
            # Directly execute to fetch the account key
            conn.execute("SELECT content FROM private_keys WHERE name = %s", (acme_key_name,))
            account_key_data = conn.fetchone()

            if not account_key_data:
                account_key = self.gen_key(acme_key_name)
            else:
                account_key = key_from_der(account_key_data[0])

        return account_key
