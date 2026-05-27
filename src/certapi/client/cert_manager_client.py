import time

import requests
from typing import Callable, List, Union, Dict, Optional, Any, Literal
from cryptography import x509
from certapi.errors import CertApiException, HttpError, NetworkError
from certapi.http.types import CertificateResponse, IssuedCert
from certapi.keystore.KeyStore import KeyStore
from certapi.crypto import Key


class CertManagerClient:
    def __init__(self, base_url: str, key_store: Optional[KeyStore] = None, timeout: int = 300):
        self.base_url = base_url.rstrip("/")
        self.key_store = key_store
        self.timeout = timeout

    def _url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        data: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> requests.Response:
        url = self._url(path)
        try:
            response = requests.request(
                method,
                url,
                params=params,
                json=json_data,
                data=data,
                headers=headers,
                timeout=self.timeout if timeout is None else timeout,
            )
        except requests.exceptions.Timeout as e:
            raise NetworkError(
                request=e.request,
                message=f"CertAPI request timed out: {method} {url}",
                detail={"method": method, "url": url, "errorType": e.__class__.__name__, "message": str(e)},
                step="CertAPI client request",
            ) from e
        except requests.exceptions.ConnectionError as e:
            raise NetworkError(
                request=e.request,
                message=f"CertAPI server is unreachable: {method} {url}",
                detail={"method": method, "url": url, "errorType": e.__class__.__name__, "message": str(e)},
                step="CertAPI client request",
            ) from e
        except requests.exceptions.RequestException as e:
            raise NetworkError(
                request=e.request,
                message=f"CertAPI network request failed: {method} {url}",
                detail={"method": method, "url": url, "errorType": e.__class__.__name__, "message": str(e)},
                step="CertAPI client request",
            ) from e

        if not 200 <= response.status_code < 300:
            detail = self._response_detail(response)
            raise HttpError(
                response=response,
                message=f"CertAPI returned HTTP {response.status_code}: {method} {url}",
                detail=detail,
                step="CertAPI client request",
            )

        return response

    def _response_detail(self, response: requests.Response) -> Dict[str, Any]:
        try:
            body = response.json()
        except ValueError:
            body = response.text[:2000]

        return {
            "statusCode": response.status_code,
            "url": response.url,
            "method": response.request.method if response.request else None,
            "body": body,
        }

    def _json_response(self, response: requests.Response) -> Any:
        try:
            return response.json()
        except ValueError as e:
            raise CertApiException(
                "CertAPI returned a successful response that was not valid JSON",
                detail=self._response_detail(response),
                step="CertAPI client response parsing",
            ) from e

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None, timeout: Optional[float] = None) -> Any:
        response = self._request("GET", path, params=params, timeout=timeout)
        return self._json_response(response)

    def _post(
        self, path: str, data: Optional[Union[Dict[str, Any], str]] = None, headers: Optional[Dict[str, str]] = None
    ) -> Any:
        response = self._request(
            "POST",
            path,
            json_data=data if isinstance(data, dict) else None,
            data=data if isinstance(data, str) else None,
            headers=headers,
        )
        return self._json_response(response)

    def setup(self, timeout: Optional[float] = None):
        """
        Check connection to the cert manager server.
        """
        return self._get("/api/health", timeout=timeout)

    def wait_healthy(
        self,
        timeout_seconds: int = 60,
        retry_interval_seconds: float = 1,
        raise_exception: bool = True,
        request_timeout_seconds: float = 5,
        cancelled_fn: Optional[Callable[[], bool]] = None,
    ) -> bool:
        """
        Wait for the cert manager server to become healthy.

        Returns ``False`` on timeout when ``raise_exception`` is disabled, or
        when ``cancelled_fn`` reports cancellation.
        """
        start_time = time.monotonic()
        deadline = start_time + timeout_seconds
        last_error = None
        while True:
            if cancelled_fn is not None and cancelled_fn():
                return False
            try:
                remaining = deadline - time.monotonic()
                self.setup(timeout=min(request_timeout_seconds, max(remaining, 0.001)))
                return True
            except CertApiException as e:
                last_error = e
                if cancelled_fn is not None and cancelled_fn():
                    return False
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    if not raise_exception:
                        return False
                    raise last_error
                elapsed_seconds = int(time.monotonic() - start_time)
                print(f"[CertApi client] Waiting for CertAPI since {elapsed_seconds} seconds")
                sleep_until = time.monotonic() + min(retry_interval_seconds, remaining)
                while True:
                    if cancelled_fn is not None and cancelled_fn():
                        return False
                    sleep_remaining = sleep_until - time.monotonic()
                    if sleep_remaining <= 0:
                        break
                    time.sleep(min(0.1, sleep_remaining))

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
        batch_domains: bool = False,
        self_verify: bool = True,
    ) -> CertificateResponse:
        return self.obtain(
            hosts=hosts,
            key_type=key_type,
            expiry_days=expiry_days,
            country=country,
            state=state,
            locality=locality,
            organization=organization,
            user_id=user_id,
            renew_threshold_days=renew_threshold_days,
            skip_failing=skip_failing,
            batch_domains=batch_domains,
            self_verify=self_verify,
        )

    def obtain(
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
        batch_domains: bool = False,
        self_verify: bool = True,
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
        params["batch_domains"] = batch_domains
        params["self_verify"] = self_verify

        data = self._get("/api/obtain", params=params)
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

        response = self._request(
            "POST", "/api/sign_csr", data=csr_pem, headers={"Content-Type": "application/x-pem-file"}
        )
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
