import requests
from .AcmeError import *


def request(method, step: str, url: str, json=None, headers=None, throw=True) -> requests.Response:
    res = None
    try:
        res = requests.request(method, url, json=json, headers=headers, timeout=15)
        print("Request [" + str(res.status_code) + "] : " + method + " " + url + " step=" + step)
    except requests.RequestException as e:
        print("Request : " + str(method) + " " + str(url) + " step=" + str(step))
        raise AcmeNetworkError(
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
    if 199 <= res.status_code > 299:
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
                raise AcmeInvaliNonceError(res, step=step)

        if throw:
            raise AcmeHttpError(res, step=step)
    return res


def post(step: str, url: str, json=None, headers=None, throw=True) -> requests.Response:
    return request("POST", step, url, json=json, headers=headers, throw=throw)


def get(step: str, url, headers=None, throw=True) -> requests.Response:
    return request("GET", step, url, headers=headers, throw=throw)
