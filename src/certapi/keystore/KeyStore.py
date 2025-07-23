import os
import sqlite3
from typing import Tuple, Optional,Union,List
from contextlib import contextmanager

from abc import ABC, abstractmethod

from certapi.crypto import Key,Certificate,certs_to_pem,cert_to_pem,certs_from_pem


class KeyStore(ABC):
    def _get_or_generate_key(self,id:str|int) -> Key:
        account_key = self.find_key(id)
        if account_key is None:
            account_key = Key.generate('ecdsa')
            id= self.save_key(account_key,id)
        return (account_key,id)
    
    def _get_cert_as_pem_bytes(cert: Union[List[Certificate],str,Certificate])->str:
        if isinstance(cert, list):
            cert_pem = certs_to_pem(cert)
        elif isinstance(cert, str):
            cert_pem = cert.encode()
        else:
            cert_pem = cert_to_pem(cert)
        return cert_pem
    
    def _get_cert_as_cert_list(cert: Union[List[Certificate],str,Certificate])->List[Certificate]:
        if isinstance(cert, list):
            return cert
        elif isinstance(cert, str):
            return certs_from_pem(cert)
        elif isinstance (cert,Certificate):
           return [cert]
        else:
            raise ValueError("Keysore.get_cet_as_cert_list(): Expected certificate convertible type got: ",cert.__class__.__name__)

    @abstractmethod
    def save_key(self, key: Key, id: str|int|None) -> int | str:
        pass

    @abstractmethod
    def find_key(self,id:str|int)-> Optional[Key]:
        pass

    @abstractmethod
    def save_cert(
        self, private_key_id: int, cert: Certificate | str | List[Certificate], domains: List[str], name: str = None
    ) -> int:
        pass


    @abstractmethod
    def find_cert_by_domain(self, domain: str) -> None | Tuple[int | str, Key, Certificate | List[Certificate]]:
        pass


    @abstractmethod
    def get_cert_by_id(self, id: str) -> None | Tuple[int | str, Key, Certificate | List[Certificate]]:
        pass




class FilesystemKeyStore(KeyStore):
    
    def __init__(self, base_dir=".", keys_dir_name="keys", certs_dir_name="certs"):
        self.keys_dir = os.path.join(base_dir, keys_dir_name)
        self.certs_dir = os.path.join(base_dir, certs_dir_name)
        os.makedirs(self.keys_dir, exist_ok=True)
        os.makedirs(self.certs_dir, exist_ok=True)
        self._init_account_key()

    def save_key(self, key:Key, id)-> int|str:
        raise NotImplementedError

    def find_key(self, id) -> Optional[Key]:
        raise NotImplementedError

    def save_cert(self, private_key_id, cert:  Certificate | str | List[Certificate], domains:List[str], name = None):
        raise NotImplementedError

    def find_cert_by_domain(self, id)->Tuple[int | str, Key, Certificate | List[Certificate]]:
        raise NotImplementedError

    def get_cert(self, domain) -> Tuple[int | str, Key, Certificate | List[Certificate]]:
        raise NotImplementedError
