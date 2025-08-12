import requests
import time
from certapi.errors import HttpError, NetworkError, CertApiException


class HttpClientBase(object):
    def __init__(self, base_url: str, headers: dict, auto_retry=False):
        self.api_base_url = base_url
        self.session = requests.Session()
        self.session.headers.update(headers)
        self.auto_retry = auto_retry

    def _req(
        self,
        method: str,
        url: str,
        step: str,
        json_data: dict = None,
        data: dict = None,
        params: dict = None,
        timeout: int = 15,
    ) -> requests.Response:
        res = None
        try:
            res = self.session.request(method, url, json=json_data, data=data, params=params, timeout=timeout)
        except requests.exceptions.ConnectionError as e:
            print("Request [" + str(res.status_code) + "] : " + method + " " + url + " step=" + str(step))
            raise NetworkError(
                request=e.request,
                message=f"Network connection error: {e}",
                detail={"errorType": e.__class__.__name__, "message": str(e), "method": method, "url": url},
                step=f"HTTP Request ({method} {url})" if step is None else step,
            ) from e
        except requests.exceptions.Timeout as e:
            print("Request [" + str(res.status_code) + "] : " + method + " " + url + " step=" + str(step))
            raise NetworkError(
                request=e.request,
                message=f"Request timed out: {e}",
                detail={"errorType": e.__class__.__name__, "message": str(e), "method": method, "url": url},
                step=f"HTTP Request ({method} {url})" if step is None else step,
            ) from e
        except requests.exceptions.RequestException as e:
            print("Request [" + str(res.status_code) + "] : " + method + " " + url + " step=" + str(step))
            raise NetworkError(
                request=e.request,
                message=f"An unexpected network error occurred: {e}",
                detail={"errorType": e.__class__.__name__, "message": str(e), "method": method, "url": url},
                step=f"HTTP Request ({method} {url})" if step is None else step,
            ) from e

        if not (200 <= res.status_code < 300):
            [print(x, y) for (x, y) in res.headers.items()]
            print("Response:", res.text)
            try:
                detail = res.json()
            except ValueError:
                detail = res.text
            raise HttpError(response=res, message=f"API error: {res.status_code}", detail=detail, step=step)
        return res

    def _req_with_retry(
        self,
        method: str,
        url: str,
        step: str,
        json_data: dict = None,
        data: dict = None,
        params: dict = None,
        timeout: int = 15,
        retry: bool = None,
        retries: int = 2,
        delay: int = 4,
    ) -> requests.Response:
        use_retry = self.auto_retry if retry is None else retry
        if not use_retry:
            return self._req(method, url, step, json_data, data, params, timeout)

        for i in range(retries + 1):
            try:
                return self._req(method, url, step, json_data, data, params, timeout)
            except CertApiException as e:
                if e.can_retry and i < retries:
                    print(f"Retrying {method} {url} in {delay} seconds due to retryable error: {e.message}")
                    time.sleep(delay)
                else:
                    e.can_retry = False
                    raise

    def _get(self, url: str, step: str, params: dict = None, retry: bool = None):
        return self._req_with_retry("GET", url, step, params=params, retry=retry)

    def _post(self, url: str, step: str, json_data: dict = None, data: dict = None, retry: bool = None):
        return self._req_with_retry("POST", url, step, json_data=json_data, data=data, retry=retry)

    def _delete(self, url: str, step: str, retry: bool = None):
        return self._req_with_retry("DELETE", url, step, retry=retry)
