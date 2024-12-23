import sqlite3
from typing import Union, Tuple

from .crypto import *
import os

account_key: RSAPrivateKey = None
acount_public_part = None

try:
    os.mkdir(
        "db",
    )
except FileExistsError as e:
    pass

conn = sqlite3.connect("db/database.db")
print("Opened database successfully")
conn.executescript(
    """
    CREATE TABLE if not exists private_keys(id INTEGER PRIMARY KEY AUTOINCREMENT,NAME varchar(50) null ,content BLOB);
    create table if not exists certificates(id INTEGER  PRIMARY KEY AUTOINCREMENT,name varchar(50) NULL 
            ,priv_id integer references private_keys not null
            ,content BLOB
            , sign_id int   references private_keys null );
    CREATE TABLE if not exists ssl_domains(domain varchar(255),certificate_id integer  references certificates);
    CREATE TABLE if not exists ssl_wildcards(domain varchar(255),certificate_id integer  references certificates);
"""
)


def init():
    global account_key
    acmeKeyName = "ACME Account Key"
    account_key = conn.execute("select (content) from private_keys where name=?", [acmeKeyName]).fetchone()
    if not account_key:
        account_key = gen_key(acmeKeyName)
    else:
        account_key = key_from_der(account_key[0])
    print(key_to_pem(account_key).decode("utf-8"))


def gen_key(name=None, size=4096) -> (int, RSAPrivateKey):
    key = gen_key_rsa(size)
    save_key(key, name)
    return key


def save_key(key, name=None) -> int:
    cur = conn.cursor()
    cur.execute("INSERT into private_keys(name,content) values (?,?)", (name, key_to_der(key)))
    cur.close()
    conn.commit()
    return cur.lastrowid


init()


def save_cert(private_key_id: int, cert: Certificate, name=None, domains=[]) -> int:
    cur = conn.cursor()
    cur.execute(
        "INSERT into certificates(name,priv_id,content) values(?,?,?)",
        (name, private_key_id, cert.public_bytes(serialization.Encoding.DER)),
    )
    cert_id = cur.lastrowid

    for d in domains:
        cur.execute("INSERT INTO ssl_domains(domain,certificate_id) values(?,?)", (d, cert_id))
    cur.close()
    conn.commit()
    return cert_id


def getCert(domain) -> Union[None, Tuple[int, bytes, bytes]]:
    c = conn.execute(
        """
        SELECT c.id ,p.content ,c.content 
        from ssl_domains s 
        join certificates c 
        join private_keys p  on c.priv_id =p.id where s.domain = ? """,
        (domain,),
    )
    res = c.fetchone()
    c.close()
    return res
