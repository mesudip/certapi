import requests
from .AcmeError import *
import json as j
import time

## I don't like the fact that the http request layer
## is doing retries internally. This has to be later refactored to be more explicit.
NETWORK_RETRY_ATTEMPTS = 2
NETWORK_RETRY_DELAY_SECONDS = 2
HTTP_RETRY_ATTEMPTS = 2
HTTP_RETRY_DELAY_SECONDS = 2


def request(method, step: str, url: str, json=None, headers=None, throw=True) -> requests.Response:
    res = None
    max_attempts = max(NETWORK_RETRY_ATTEMPTS, HTTP_RETRY_ATTEMPTS)
    for attempt in range(max_attempts + 1):
        try:
            res = requests.request(method, url, json=json, headers=headers, timeout=15)
            print("Request [" + str(res.status_code) + "] : " + method + " " + url + " step=" + step)
            if throw and 500 <= res.status_code <= 599 and attempt < HTTP_RETRY_ATTEMPTS:
                time.sleep(HTTP_RETRY_DELAY_SECONDS)
                continue
            break
        except requests.RequestException as e:
            if attempt < NETWORK_RETRY_ATTEMPTS:
                time.sleep(NETWORK_RETRY_DELAY_SECONDS)
                continue
            print("Request : " + str(method) + " " + str(url) + " step=" + str(step))
            acme_error = AcmeNetworkError(
                e.request,
                f"Error communicating with ACME server",
                {
                    "errorType": e.__class__.__name__,
                    "message": str(e),
                    "method": method,
                    "url": e.request.url if e.request else None,
                },
                step,
            )
            # Network retries are already exhausted in this layer.
            acme_error.can_retry = False
            raise acme_error
    if 199 <= res.status_code > 299:
        if json:
            print("Request:", j.dumps(json))
        [print(x, y) for (x, y) in res.headers.items()]
        print("Response:", res.text)
        json_data = None
        try:
            json_data = res.json()
        except requests.RequestException as e:
            pass
        if json_data and json_data.get("type"):
            errorType = json_data["type"]
            if errorType == "urn:ietf:params:acme:error:badNonce":
                raise AcmeInvalidNonceError(res, step=step)

        if throw:
            raise AcmeHttpError(res, step=step)
    return res


def post(step: str, url: str, json=None, headers=None, throw=True) -> requests.Response:
    return request("POST", step, url, json=json, headers=headers, throw=throw)


def get(step: str, url, headers=None, throw=True) -> requests.Response:
    return request("GET", step, url, headers=headers, throw=throw)
