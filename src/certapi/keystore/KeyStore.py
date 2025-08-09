import os
import sqlite3
from typing import Literal, Tuple, Optional, Union, List
from contextlib import contextmanager

from abc import ABC, abstractmethod

from certapi.crypto import Key, Certificate, certs_to_pem, cert_to_pem, certs_from_pem


class KeyStore(ABC):
    def _get_or_generate_key(self, id: str | int, key_type: Literal["rsa", "ecdsa", "ed25519"] = "ecdsa") -> Key:
        account_key = self.find_key_by_id(id)
        if account_key is None:
            account_key = Key.generate(key_type)
            id = self.save_key(account_key, id)
        return (account_key, id)

    def _get_cert_as_pem_bytes(self, cert: Union[List[Certificate], str, Certificate]) -> bytes:
        if isinstance(cert, list):
            cert_pem = certs_to_pem(cert)
        elif isinstance(cert, str):
            cert_pem = cert.encode()
        else:
            cert_pem = cert_to_pem(cert)
        return cert_pem

    def _get_cert_as_cert_list(self, cert: Union[List[Certificate], str, Certificate]) -> List[Certificate]:
        if isinstance(cert, list):
            return cert
        elif isinstance(cert, str):
            return certs_from_pem(cert.encode())  # Ensure it's bytes for certs_from_pem
        elif isinstance(cert, (bytes, memoryview)):  # Handle bytes and memoryview
            return certs_from_pem(bytes(cert))  # Convert memoryview to bytes
        elif isinstance(cert, Certificate):
            return [cert]
        else:
            raise ValueError(
                "KeyStore._get_cert_as_cert_list(): Expected certificate convertible type got: ",
                cert.__class__.__name__,
            )

    @abstractmethod
    def save_key(self, key: Key, name: str | int | None) -> int | str:
        pass

    @abstractmethod
    def find_key_by_id(self, id: str | int) -> Optional[Key]:
        pass

    @abstractmethod
    def find_key_by_name(self, id: str | int) -> Optional[Key]:
        pass

    @abstractmethod
    def save_cert(
        self,
        private_key_id: int | str,
        cert: Certificate | str | List[Certificate],
        domains: List[str],
        name: str = None,
    ) -> int:
        pass

    @abstractmethod
    def find_key_and_cert_by_domain(self, domain: str) -> None | Tuple[int | str, Key, List[Certificate]]:
        pass

    @abstractmethod
    def find_key_and_cert_by_cert_id(self, id: str) -> None | Tuple[Key, List[Certificate]]:
        pass
