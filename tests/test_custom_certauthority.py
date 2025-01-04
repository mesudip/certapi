import pytest
from cryptography.hazmat.primitives import serialization
from certapi.crypto import gen_key_rsa, key_to_pem
from certapi.custom_certauthority import CustomCertAuthority
import os
from contextlib import contextmanager


@pytest.fixture
def rsa_key():
    return gen_key_rsa()


test_new_file_dir = "./build/tests/intemediate-files"
os.makedirs(test_new_file_dir, exist_ok=True)


@contextmanager
def tmp_test_file(filename):
    with open(os.path.join(test_new_file_dir, filename), "wb") as f:
        yield f


def write_tmp_file(filename, content):
    with tmp_test_file(filename) as f:
        f.write(content)


def test_self_sign_certificat(rsa_key):
    certauthority = CustomCertAuthority(rsa_key)
    (key, cert) = certauthority.create_cert("sudip.sireto.io", key_type="rsa")
    write_tmp_file("test_self_sign_private.key", key_to_pem(key))
    write_tmp_file("test_self_sign_certificate.crt", cert.public_bytes(serialization.Encoding.PEM))

    with tmp_test_file("test_self_sign_certificate.p12") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        f.write(key_to_pem(key))


def test_get_ca(rsa_key):
    certauthority = CustomCertAuthority(rsa_key)
    cert = certauthority.get_ca_cert()
    write_tmp_file("test_self_sign_ca.crt", cert.public_bytes(serialization.Encoding.PEM))
