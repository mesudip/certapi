from ast import List
import os

from certapi.crypto import certs_from_pem
from .KeyStore import KeyStore
from typing import Tuple, Optional, Union
from certapi.crypto import Key,Certificate

class FilesystemKeyStore(KeyStore):
    def __init__(self, base_dir=".", keys_dir_name="keys", certs_dir_name="certs"):
        self.keys_dir = os.path.join(base_dir, keys_dir_name)
        self.certs_dir = os.path.join(base_dir, certs_dir_name)
        os.makedirs(self.keys_dir, exist_ok=True)
        os.makedirs(self.certs_dir, exist_ok=True)


    def save_key(self, key: Key, name: str = None) -> str:
        key_path = os.path.join(self.keys_dir, f"{name}.key")
        with open(key_path, "wb") as f:
            f.write(key.to_pem())
        return name  # Dummy ID since filesystem does not use numeric IDs


    def find_key(self, name: str) -> Union[None, Key]:
        key_path = os.path.join(self.keys_dir, f"{name}.key")
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                key_data = f.read()
            return Key.from_pem(key_data)
        return None

    def find_cert(self, name: str) -> Union[None, str]:
        cert_path = os.path.join(self.certs_dir, f"{name}.crt")
        if os.path.exists(cert_path):
            with open(cert_path, "rb") as f:
                return  f.read()
        return None

    def save_cert(
        self, private_key_id: str, cert: Certificate | str | List[Certificate], domains: list, name: str = None
    ) -> int:
        cert_pem= self._get_cert_as_pem_bytes(cert)

        if name:
            cert_path = os.path.join(self.certs_dir, f"{name}.crt")
            with open(cert_path, "wb") as f:
                f.write(cert_pem)

        key_content = None
        key_path = os.path.join(self.keys_dir, f"{private_key_id}.key")
        with open(key_path, "rb") as f:
            key_content = f.read()

        for domain in domains:
            domain_name = domain
            if name is not None and name.endswith(".selfsigned"):
                domain_name += ".selfsigned"

            if domain_name != private_key_id:
                with open(os.path.join(self.keys_dir, f"{domain_name}.key"), "wb") as f:
                    f.write(key_content)

            domain_cert_path = os.path.join(self.certs_dir, f"{domain_name}.crt")
            with open(domain_cert_path, "wb") as f:
                f.write(cert_pem)

        # Dummy ID since filesystem does not use numeric IDs
        return name if name else domains[0]  

    def get_cert(self, name: str) -> None | Tuple[str, Key, List[Certificate]]:
        cert_path = os.path.join(self.certs_dir, f"{name}.crt")
        key_path = os.path.join(self.keys_dir, f"{name}.key")
        key = None
        cert = None
        if os.path.exists(key_path):
            try:
                with open(key_path, "rb") as f:
                    key = Key.from_pem(f.read())
            except ValueError:
                pass

        if os.path.exists(cert_path):
            try:
                with open(cert_path, "rb") as f:
                    cert = certs_from_pem(f.read())
            except ValueError:
                pass

        if cert is None or key is None:
            return None
        return (name, key, cert)