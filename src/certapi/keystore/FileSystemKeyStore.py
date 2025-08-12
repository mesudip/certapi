import os
from typing import Tuple, Optional, Union, List

from certapi.crypto import certs_from_pem
from .KeyStore import KeyStore
from certapi.crypto import Key, Certificate


class FileSystemKeyStore(KeyStore):
    """
    Important nuance of using filesystem keystores is that id and name means same thing.
    """

    def __init__(self, base_dir=".", keys_dir_name="keys", certs_dir_name="certs"):
        self.keys_dir = os.path.join(base_dir, keys_dir_name)
        self.certs_dir = os.path.join(base_dir, certs_dir_name)
        os.makedirs(self.keys_dir, exist_ok=True)
        os.makedirs(self.certs_dir, exist_ok=True)

    def save_key(self, key: Key, name: str | None) -> str:
        name = str(name)
        key_path = os.path.join(self.keys_dir, f"{name}.key")
        with open(key_path, "wb") as f:
            f.write(key.to_pem())
        return name

    def find_key_by_id(self, id: str | int) -> Union[None, Key]:
        name = str(id)
        key_path = os.path.join(self.keys_dir, f"{name}.key")
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                key_data = f.read()
            try:
                return Key.from_pem(key_data)
            except:
                pass
        return None

    def find_key_by_name(self, name: str) -> Optional[Key]:
        return self.find_key_by_id(name)

    def save_cert(
        self, private_key_id: str, cert: Certificate | str | List[Certificate], domains: list, name: str = None
    ) -> int:
        cert_pem = self._get_cert_as_pem_bytes(cert)

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

        return name

    def find_key_and_cert_by_domain(self, domain: str) -> None | Tuple[str, Key, List[Certificate]]:
        return self._get_key_and_cert_by_name(domain)

    def find_key_and_cert_by_cert_id(self, id: str) -> None | Tuple[Key, List[Certificate]]:

        key_path = os.path.join(self.keys_dir, f"{id}.key")
        cert_path = os.path.join(self.certs_dir, f"{id}.crt")
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
        return (key, cert)

    def _get_key_and_cert_by_name(self, name: str) -> None | Tuple[str, Key, List[Certificate]]:
        result = self.find_key_and_cert_by_cert_id(name)
        if result is not None:
            return (name, result[0], result[1])
