
from contextlib import contextmanager

from certapi.keystore.KeyStore import KeyStore


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

    def save_cert(
        self, private_key_id: int, cert: Certificate | str | List[Certificate], domains: List[str], name: str = None
    ) -> int:
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
