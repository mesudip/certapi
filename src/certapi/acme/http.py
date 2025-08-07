import requests
from .AcmeError import *


def request(method, step: str, url: str, json=None, headers=None, throw=True) -> requests.Response:
    res = None
    try:
        res = requests.request(method, url, json=json, headers=headers, timeout=15)
        print("Request [" + str(res.status_code) + "] : " + method + " " + url + " step=" + step)
    except requests.HTTPError as e:
        status = res.status_code if res else None
        status = status if status else (e.response.status_code if e.response else None)
        if status:
            print("Request [" + str(status) + "] : " + method + " " + url + " step=" + step)
        else:
            print("Request : " + method + " " + url + " step=" + step)

        raise e
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


def get(step: str, url) -> requests.Response:
    return request("GET", step, url)
