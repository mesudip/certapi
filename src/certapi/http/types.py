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
        return f"(domains: {self.domains}, certificate:{self.certificate})"

    def to_json(self):
        return {"privateKey": self.privateKey, "certificate": self.certificate, "domains": self.domains}


class FailedDomains:
    """
    One issuance batch that could not be obtained.

    Only carries the error name, message and step. The originating exception's `detail`
    holds raw ACME/DNS-provider response bodies and is deliberately not exposed here,
    since this crosses the HTTP boundary to remote clients.
    """

    def __init__(self, *, domains: List[str] = None, name: str = None, message: str = None, step: str = None):
        self.domains: List[str] = domains or []
        self.name = name
        self.message = message
        self.step = step

    @staticmethod
    def from_exception(domains: List[str], error: Exception) -> "FailedDomains":
        return FailedDomains(
            domains=list(domains),
            name=type(error).__name__,
            message=getattr(error, "message", None) or str(error),
            step=getattr(error, "step", None),
        )

    @staticmethod
    def from_json(data: Dict[str, Any]) -> "FailedDomains":
        return FailedDomains(
            domains=data.get("domains", []),
            name=data.get("name"),
            message=data.get("message"),
            step=data.get("step"),
        )

    def __repr__(self):
        return f"FailedDomains(domains={self.domains}, name={self.name})"

    def __str__(self):
        step = f" @ {self.step}" if self.step else ""
        return f"(domains: {self.domains}, error: {self.name}{step}: {self.message})"

    def to_json(self):
        return {"domains": self.domains, "name": self.name, "message": self.message, "step": self.step}


class CertificateResponse:
    def __init__(
        self,
        *,
        existing: List[IssuedCert] = None,
        issued: List[IssuedCert] = None,
        failed: List[FailedDomains] = None,
    ):
        self.existing: List[IssuedCert] = existing or []
        self.issued: List[IssuedCert] = issued or []
        self.failed: List[FailedDomains] = failed or []

    @staticmethod
    def from_json(data: Dict[str, Any]) -> "CertificateResponse":
        return CertificateResponse(
            existing=[IssuedCert.from_json(cert_data) for cert_data in data.get("existing", [])],
            issued=[IssuedCert.from_json(cert_data) for cert_data in data.get("issued", [])],
            failed=[FailedDomains.from_json(failure) for failure in data.get("failed", [])],
        )

    def __repr__(self):
        return f"CertificateResponse(existing={self.existing}, issued={self.issued}, failed={self.failed})"

    def __str__(self):
        parts = [f"existing: {self.existing}"]
        if self.issued:
            parts.append(f"new: {self.issued}")
        if self.failed:
            parts.append(f"failed: {self.failed}")
        return f"({', '.join(parts)})"

    def to_json(self):
        data = {
            "existing": [x.to_json() for x in self.existing],
            "issued": [x.to_json() for x in self.issued],
        }
        if self.failed:
            data["failed"] = [x.to_json() for x in self.failed]
        return data
