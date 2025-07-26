import pytest
import requests
from typing import List, Dict, Any
from cryptography import x509
from certapi.crypto.crypto import cert_to_pem, certs_to_pem
from certapi import RemoteCertAuthority, CertificateResponse, IssuedCert, ListCertsResponse

BASE_URL = "http://192.168.1.67:8082"
AUTH_HEADERS = {"Authorization": "Bearer test_token"}

@pytest.fixture
def remote_ca():
    return RemoteCertAuthority(BASE_URL, AUTH_HEADERS)

def test_obtain_cert_regular_domain(remote_ca:RemoteCertAuthority):
    hostnames = ["example.com"]
    response: CertificateResponse = remote_ca.obtain_cert(hostnames)

    assert isinstance(response, CertificateResponse)
    assert len(response.issued) == 0
    assert len(response.existing) == 0

def test_obtain_cert_wildcard_domain(remote_ca):
    hostnames = ["*.example.com"]
    response: CertificateResponse = remote_ca.obtain_cert(hostnames)

    assert isinstance(response, CertificateResponse)
    assert len(response.issued) == 0
    assert len(response.existing) == 0

def test_obtain_cert_multiple_domains(remote_ca):
    hostnames = ["example.com", "example.org"]
    response: CertificateResponse = remote_ca.obtain_cert(hostnames)

    assert isinstance(response, CertificateResponse)
    assert len(response.issued) == 0
    assert len(response.existing) == 0

def test_obtain_cert_api_error(remote_ca):
    remote_ca.base_url = "http://localhost:9999"
    hostnames = ["example.com"]
    with pytest.raises(Exception) as context:
        remote_ca.obtain_cert(hostnames)

    assert isinstance(context.value, Exception)

def test_list_certs(remote_ca):
    response: ListCertsResponse = remote_ca.list_certs()

    assert isinstance(response, ListCertsResponse)
    assert response.username == "sudip"
    assert response.theme == "light"
    assert response.k2 == "v"
