import requests
from typing import List, Union, Dict, Optional, Any, Literal
from cryptography import x509
from certapi.http.types import CertificateResponse, IssuedCert
from certapi.keystore.KeyStore import KeyStore
from certapi.crypto import Key


class CertManagerClient:
    def __init__(self, base_url: str, key_store: Optional[KeyStore] = None):
        self.base_url = base_url
        self.key_store = key_store

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        response = requests.get(f"{self.base_url}{path}", params=params)
        response.raise_for_status()
        return response.json()

    def _post(
        self, path: str, data: Optional[Union[Dict[str, Any], str]] = None, headers: Optional[Dict[str, str]] = None
    ) -> Any:
        response = requests.post(
            f"{self.base_url}{path}",
            json=data if isinstance(data, dict) else None,
            data=data if isinstance(data, str) else None,
            headers=headers,
        )
        response.raise_for_status()
        return response.json()

    def setup(self):
        """
        Check connection to the cert manager server.
        """
        try:
            self._get("/keys")
        except Exception as e:
            print(f"Warning: CertManagerClient could not connect to {self.base_url}: {e}")

    def issue_certificate(
        self,
        hosts: Union[str, List[str]],
        key_type: Literal["rsa", "ecdsa", "ed25519"] = "ecdsa",
        expiry_days: int = 90,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        user_id: Optional[str] = None,
        renew_threshold_days: Optional[int] = None,
        skip_failing: bool = True,
    ) -> CertificateResponse:
        params = {
            "hostname": hosts if isinstance(hosts, str) else hosts,
            "key_type": key_type,
            "expiry_days": expiry_days,
        }
        if country:
            params["country"] = country
        if state:
            params["state"] = state
        if locality:
            params["locality"] = locality
        if organization:
            params["organization"] = organization
        if user_id:
            params["user_id"] = user_id
        if renew_threshold_days is not None:
            params["renew_threshold_days"] = renew_threshold_days
        params["skip_failing"] = skip_failing

        data = self._get("/obtain", params=params)
        res = CertificateResponse.from_json(data)

        if self.key_store:
            for cert_data in res.issued + res.existing:
                if cert_data.privateKey and cert_data.certificate:
                    try:
                        key = Key.from_pem(cert_data.privateKey.encode("utf-8"))
                        key_id = self.key_store.save_key(key, cert_data.domains[0])
                        self.key_store.save_cert(key_id, cert_data.certificate, cert_data.domains)
                    except Exception as e:
                        print(f"Warning: Failed to save certificate for {cert_data.domains} to KeyStore: {e}")
                        raise e
        return res

    def issue_certificate_for_csr(self, csr: Union[str, x509.CertificateSigningRequest]) -> str:
        if not isinstance(csr, str):
            from ..crypto import csr_to_pem

            csr_pem = csr_to_pem(csr).decode("utf-8")
        else:
            csr_pem = csr

        response = requests.post(
            f"{self.base_url}/sign_csr", data=csr_pem, headers={"Content-Type": "application/x-pem-file"}
        )
        response.raise_for_status()
        return response.text

    def list_keys(self) -> List[Dict[str, str]]:
        return self._get("/keys")

    def get_key_by_id(self, key_id: str) -> Optional[Dict[str, str]]:
        try:
            return self._get(f"/keys/{key_id}")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return None
            raise

    def get_key_by_name(self, name: str) -> Optional[Dict[str, str]]:
        try:
            return self._get(f"/keys/name/{name}")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return None
            raise

    def save_key(self, pem: str, name: str) -> Dict[str, Any]:
        data = {"pem": pem, "name": name}
        return self._post("/keys", data=data)

    def list_certs(self) -> List[Dict[str, str]]:
        return self._get("/certs")

    def get_cert_by_id(self, cert_id: str) -> Optional[Dict[str, str]]:
        try:
            return self._get(f"/certs/{cert_id}")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return None
            raise

    def get_cert_by_domain(self, domain: str) -> Optional[Dict[str, str]]:
        try:
            return self._get("/certs", params={"domain": domain})
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return None
            raise

    def save_cert(
        self, private_key_id: Union[int, str], cert_pem: str, domains: List[str], name: Optional[str] = None
    ) -> Dict[str, Any]:
        data = {
            "private_key_id": private_key_id,
            "cert": cert_pem,
            "domains": domains,
        }
        if name:
            data["name"] = name
        return self._post("/certs", data=data)
