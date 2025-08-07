from contextlib import contextmanager
from typing import Tuple, Optional, Union, List

from certapi.crypto import Key, Certificate, certs_from_pem, cert_to_pem, certs_to_pem
from .KeyStore import KeyStore


class PostgresKeyStore(KeyStore):
    def __init__(self, db_url="postgresql://user:password@localhost/dbname"):
        self.db_url = db_url
        import psycopg2

        self.psycopg2 = psycopg2
        self._initialize_pool()
        self._initialize_db()

    def _initialize_pool(self):
        """Initialize the connection pool."""
        from psycopg2.pool import SimpleConnectionPool

        self.pool = SimpleConnectionPool(1, 10, self.db_url)

    def _check_connection(self, conn):
        """Check if the connection is alive by executing a simple query."""
        try:
            # Attempt to execute a simple query to check connection health
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
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
            with conn.cursor() as cur:
                cur.execute(
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
            conn.commit()

    def save_key(self, key: Key, name: str | int | None) -> int | str:
        """Saves a private key in the database."""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                if name is None:
                    cur.execute("INSERT INTO private_keys (content) VALUES (%s) RETURNING id", (key.to_der(),))
                    key_id = cur.fetchone()[0]
                    conn.commit()
                    return key_id
                elif isinstance(name, int):
                    cur.execute(
                        "INSERT INTO private_keys (id, content) VALUES (%s, %s) RETURNING id", (name, key.to_der())
                    )
                    key_id = cur.fetchone()[0]
                else:  # isinstance(name, str)
                    cur.execute(
                        "INSERT INTO private_keys (name, content) VALUES (%s, %s) RETURNING id", (name, key.to_der())
                    )
                    key_id = cur.fetchone()[0]
                conn.commit()
                return name if isinstance(name, str) else key_id

    def find_key_by_id(self, id: str | int) -> Optional[Key]:
        """Finds a private key in the database by its ID."""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                if isinstance(id, int):
                    cur.execute("SELECT content FROM private_keys WHERE id = %s", (id,))
                else:
                    cur.execute("SELECT content FROM private_keys WHERE name = %s", (id,))
                res = cur.fetchone()
                if res:
                    return Key.from_der(res[0])
            return None

    def find_key_by_name(self, name: str) -> Optional[Key]:
        """Finds a private key in the database by its name."""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT content FROM private_keys WHERE name = %s", (name,))
                res = cur.fetchone()
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
        """Saves a certificate along with associated domains."""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                # Ensure private_key_id is an integer ID from the private_keys table
                if isinstance(private_key_id, str):
                    cur.execute("SELECT id FROM private_keys WHERE name = %s", (private_key_id,))
                    result = cur.fetchone()
                    if result:
                        private_key_id = result[0]
                    else:
                        raise ValueError(f"Private key with name '{private_key_id}' not found.")

                cert_data = self._get_cert_as_pem_bytes(cert)

                # Insert certificate and associated domains directly
                cur.execute(
                    "INSERT INTO certificates (name, priv_id, content) VALUES (%s, %s, %s) RETURNING id",
                    (name, private_key_id, cert_data),
                )
                cert_id = cur.fetchone()[0]

                # Insert associated domains
                for domain in domains:
                    cur.execute("INSERT INTO ssl_domains (domain, certificate_id) VALUES (%s, %s)", (domain, cert_id))
                conn.commit()
            return cert_id

    def find_cert_by_domain(self, domain: str) -> None | Tuple[int | str, Key, List[Certificate]]:
        """Fetches a certificate and its associated private key for a domain."""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                # Directly execute and fetch result
                cur.execute(
                    """
                    SELECT c.id, p.content, c.content
                    FROM ssl_domains s
                    JOIN certificates c ON s.certificate_id = c.id
                    JOIN private_keys p ON c.priv_id = p.id
                    WHERE s.domain = %s
                """,
                    (domain,),
                )
                res = cur.fetchone()

                if res:
                    return (res[0], Key.from_der(res[1]), self._get_cert_as_cert_list(res[2]))
            return None

    def find_key_and_cert_by_domain(self, domain: str) -> None | Tuple[int | str, Key, List[Certificate]]:
        """Fetches a certificate and its associated private key for a domain."""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT c.id, p.content, c.content
                    FROM ssl_domains s
                    JOIN certificates c ON s.certificate_id = c.id
                    JOIN private_keys p ON c.priv_id = p.id
                    WHERE s.domain = %s
                    """,
                    (domain,),
                )
                res = cur.fetchone()
                if res:
                    return (res[0], Key.from_der(res[1]), self._get_cert_as_cert_list(res[2]))
            return None

    def find_key_and_cert_by_cert_id(self, id: str) -> None | Tuple[Key, List[Certificate]]:
        """Fetches a private key and its associated certificate by certificate ID."""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT p.content, c.content
                    FROM certificates c
                    JOIN private_keys p ON c.priv_id = p.id
                    WHERE c.id = %s
                    """,
                    (id,),
                )
                res = cur.fetchone()
                if res:
                    key = Key.from_der(res[0])
                    certs = self._get_cert_as_cert_list(res[1])
                    return (key, certs)
            return None

    def get_cert_by_id(self, id: str) -> None | Tuple[int | str, Key, List[Certificate]]:
        """Fetches a certificate and its associated private key by ID."""
        with self.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT c.id, p.content, c.content
                    FROM certificates c
                    JOIN private_keys p ON c.priv_id = p.id
                    WHERE c.id = %s
                """,
                    (id,),
                )
                res = cur.fetchone()
                if res:
                    return (res[0], Key.from_der(res[1]), self._get_cert_as_cert_list(res[2]))
            return None
