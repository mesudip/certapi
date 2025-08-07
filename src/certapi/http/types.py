from __future__ import annotations
from typing import List, Dict, Any, Union, Optional
from cryptography.x509 import Certificate
from ..crypto.crypto import cert_to_pem, certs_to_pem
from ..crypto.crypto_classes import Key


class IssuedCert:
    def __init__(
        self,
        *,
        key: Union[str, Key] = None,
        cert: Union[str, Certificate, List[Certificate]] = None,
        domains: List[str] = None,
    ):
        if isinstance(key, Key):
            key = key.to_pem().decode("utf-8")
        elif isinstance(key, bytes):
            key = key.decode("utf-8")

        if isinstance(cert, list):
            cert = certs_to_pem(cert).decode("utf-8")
        elif isinstance(cert, Certificate):
            cert = cert_to_pem(cert).decode("utf-8")
        elif isinstance(cert, bytes):
            cert = cert.decode("utf-8")

        self.privateKey = key
        self.certificate = cert
        self.domains = domains

    @staticmethod
    def from_json(data: Dict[str, Any]) -> "IssuedCert":
        return IssuedCert(
            key=data.get("privateKey"),
            cert=data.get("certificate"),
            domains=data.get("domains", []),
        )

    def __repr__(self):
        return f"IssuedCert(domains={self.domains})"

    def __str__(self):
        return f"(hosts: {self.domains}, certificate:{self.certificate})"

    def to_json(self):
        return {"privateKey": self.privateKey, "certificate": self.certificate, "domains": self.domains}


class CertificateResponse:
    def __init__(self, *, existing: List[IssuedCert] = None, issued: List[IssuedCert] = None):
        self.existing: List[IssuedCert] = existing or []
        self.issued: List[IssuedCert] = issued or []

    @staticmethod
    def from_json(data: Dict[str, Any]) -> "CertificateResponse":
        return CertificateResponse(
            existing=[IssuedCert.from_json(cert_data) for cert_data in data.get("existing", [])],
            issued=[IssuedCert.from_json(cert_data) for cert_data in data.get("issued", [])],
        )

    def __repr__(self):
        return f"CertificateResponse(existing={self.existing}, issued={self.issued})"

    def __str__(self):
        if self.issued:
            return f"(existing: {self.existing}, new: {self.issued})"
        else:
            return f"(existing: {self.existing})"

    def to_json(self):
        return {
            "existing": [x.to_json() for x in self.existing],
            "issued": [x.to_json() for x in self.issued],
        }
