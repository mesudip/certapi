import requests
from typing import List, Dict, Any, Optional

from .http.types import CertificateResponse, IssuedCert, ListCertsResponse

class RemoteCertAuthority:
    def __init__(self, base_url: str, auth_headers: Optional[Dict[str, str]] = None):
        self.base_url = base_url.rstrip('/')
        self.auth_headers = auth_headers or {}
        self.session = requests.Session()
        self.session.headers.update(self.auth_headers)

    def _request(self, method: str, endpoint: str, **kwargs) -> Any:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        try:
            print(">> ",method,url,kwargs)
            response = self.session.request(method, url, timeout=(2, 180), **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"Error making request to {url}: {str(e)}")

    def obtain_cert(self, hostnames: List[str]) -> "CertificateResponse":
        params = {'hostname': hostnames}
        data = self._request('GET', 'obtain', params=params)
        return CertificateResponse.from_json(data)


    def get_acme_challenge(self, cid: str) -> Optional[str]:
        response = self._request('GET',f".well-known/acme-challenge/{cid}", timeout=2,)
        return response.text if response.status_code == 200 else None
