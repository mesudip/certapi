from typing import Optional, Union, List, Tuple
from certapi.keystore.KeyStore import KeyStore
from certapi.client.cert_manager_client import CertManagerClient
from certapi.crypto import Key, Certificate, certs_from_pem, cert_to_pem, certs_to_pem, key_to_pem
import requests


class RemoteKeyStore(KeyStore):
    def __init__(self, base_url: str):
        self.client = CertManagerClient(base_url)

    def save_key(self, key: Key, name: str | int | None) -> int | str:
        key_pem = key_to_pem(key).decode("utf-8")
        response = self.client.save_key(key_pem, str(name))
        return response.get("id")

    def find_key_by_id(self, id: str | int) -> Optional[Key]:
        key_data = self.client.get_key_by_id(str(id))
        if key_data and "pem" in key_data:
            return Key.from_pem(key_data["pem"].encode("utf-8"))
        return None

    def find_key_by_name(self, name: str | int) -> Optional[Key]:
        key_data = self.client.get_key_by_name(str(name))
        if key_data and "pem" in key_data:
            return Key.from_pem(key_data["pem"].encode("utf-8"))
        return None

    def save_cert(
        self,
        private_key_id: int | str,
        cert: Certificate | str | List[Certificate],
        domains: List[str],
        name: str = None,
    ) -> int:
        cert_pem = self._get_cert_as_pem_bytes(cert).decode("utf-8")
        response = self.client.save_cert(private_key_id, cert_pem, domains, name)
        return response.get("id")

    def find_key_and_cert_by_domain(self, domain: str) -> None | Tuple[int | str, Key, List[Certificate]]:
        cert_data = self.client.get_cert_by_domain(domain)
        if cert_data and "pem" in cert_data and "key_id" in cert_data:
            cert_list = certs_from_pem(cert_data["pem"].encode("utf-8"))
            key_obj = self.find_key_by_id(cert_data["key_id"])  # Assuming key_id is sufficient to retrieve the key
            if key_obj:
                return cert_data["key_id"], key_obj, cert_list
        return None

    def find_key_and_cert_by_cert_id(self, id: str) -> None | Tuple[Key, List[Certificate]]:
        cert_data = self.client.get_cert_by_id(id)
        if cert_data and "pem" in cert_data and "key_id" in cert_data:
            cert_list = certs_from_pem(cert_data["pem"].encode("utf-8"))
            key_obj = self.find_key_by_id(cert_data["key_id"])  # Assuming key_id is sufficient to retrieve the key
            if key_obj:
                return key_obj, cert_list
        return None
