import sqlite3
from typing import Union, Tuple

from .crypto import *
from certmanager import crypto
import os

account_key: RSAPrivateKey = None
acount_public_part = None

try:
    os.mkdir("db", )
except FileExistsError as e:
    pass

conn = sqlite3.connect('db/database.db')
print("Opened database successfully")
conn.executescript("""
    CREATE TABLE if not exists private_keys(id INTEGER PRIMARY KEY AUTOINCREMENT,NAME varchar(50) null ,content BLOB);
    create table if not exists certificates(id INTEGER  PRIMARY KEY AUTOINCREMENT,name varchar(50) NULL 
            ,priv_id integer references private_keys not null
            ,content BLOB
            , sign_id int   references private_keys null );
    CREATE TABLE if not exists ssl_domains(domain varchar(255),certificate_id integer  references certificates);
    CREATE TABLE if not exists ssl_wildcards(domain varchar(255),certificate_id integer  references certificates);
""")


def init():
    global account_key
    account_key = conn.execute('select (content) from private_keys where name="ACME Account Key"').fetchone()
    if not account_key:
        key = gen_key()
        account_key = key
        conn.execute('insert into private_keys(NAME,content) values (?,?)', ("ACME Account Key", key_to_der(key)))
        conn.commit()
    else:
        account_key = key_from_der(account_key[0])
    print(key_to_pem(account_key).decode("utf-8"))
    acount_public_part = account_key.public_key().public_numbers()


init()


def gen_key(name=None, size=2048) -> (int, RSAPrivateKey):
    return save_key(crypto.gen_key(size), name)


def save_key(RSAPrivateKey, name=None) -> int:
    cur = conn.cursor()
    cur.execute('INSERT into private_keys(name,content) values (?,?)', (name, key_to_der(key)))
    cur.close()
    conn.commit()
    return cur.lastrowid


def save_cert(private_key_id: int, cert: Certificate, name=None, domains=[]) -> int:
    cur = conn.cursor()
    cur.execute('INSERT into certificates(name,priv_id,content) values(?,?,?)',
                (name, private_key_id, cert.public_bytes(crypto.serialization.Encoding.DER)))
    cert_id = cur.lastrowid

    for d in domains:
        cur.execute("INSERT INTO ssl_domains(domain,certificate_id) values(?,?)", (d, cert_id))
    cur.close()
    conn.commit()
    return cert_id


def getCert(domain) -> Union[None, Tuple[int, bytes, bytes]]:
    c = conn.execute("""
        SELECT c.id  ,p.content ,c.content 
        from ssl_domains s 
        join certificates c 
        join private_keys p  on c.priv_id =p.id where s.domain = ? """, (domain,))
    res = c.fetchone()
    c.close()
    return res
