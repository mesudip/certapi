
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

    def save_cert(
        self, private_key_id: int, cert: Certificate | str | List[Certificate], domains: List[str], name: str = None
    ) -> int:
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

