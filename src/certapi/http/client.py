import requests
from certapi.errors import NetworkError, HttpError


def request(method: str, url: str, step: str = None, json=None, headers=None, throw=True, timeout=15) -> requests.Response:
    res = None
    try:
        res = requests.request(method, url, json=json, headers=headers, timeout=timeout)
        print("Request [" + str(res.status_code) + "] : " + method + " " + url + " step=" + str(step))
    except requests.exceptions.ConnectionError as e:
        raise NetworkError(
            request=e.request,
            message=f"Network connection error: {e}",
            detail={"errorType": e.__class__.__name__, "message": str(e), "method": method, "url": url},
            step=f"HTTP Request ({method} {url})" if step is None else step
        ) from e
    except requests.exceptions.Timeout as e:
        raise NetworkError(
            request=e.request,
            message=f"Request timed out: {e}",
            detail={"errorType": e.__class__.__name__, "message": str(e), "method": method, "url": url},
            step=f"HTTP Request ({method} {url})" if step is None else step
        ) from e
    except requests.exceptions.RequestException as e:
        # This catches other requests-related errors, including HTTPError
        if isinstance(e, requests.exceptions.HTTPError):
            # If it's an HTTPError, it means a response was received, but with a bad status code
            raise HttpError(
                response=e.response,
                message=f"HTTP error: {e}",
                detail={"errorType": e.__class__.__name__, "message": str(e), "method": method, "url": url},
                step=f"HTTP Request ({method} {url})" if step is None else step
            ) from e
        else:
            # For other RequestExceptions (e.g., TooManyRedirects, MissingSchema)
            raise NetworkError(
                request=e.request,
                message=f"An unexpected network error occurred: {e}",
                detail={"errorType": e.__class__.__name__, "message": str(e), "method": method, "url": url},
                step=f"HTTP Request ({method} {url})" if step is None else step
            ) from e

    if 199 <= res.status_code > 299:
        if throw:
            raise HttpError(
                response=res,
                message=f"Received status={res.status_code} from server",
                detail={"response_text": res.text, "headers": dict(res.headers)},
                step=f"HTTP Response ({method} {url})" if step is None else step
            )
    return res


def get(url: str, step: str = None, headers=None, throw=True) -> requests.Response:
    return request("GET", url, step=step, headers=headers, throw=throw)


def post(url: str, step: str = None, json=None, headers=None, throw=True) -> requests.Response:
    return request("POST", url, step=step, json=json, headers=headers, throw=throw)


def delete(url: str, step: str = None, headers=None, throw=True) -> requests.Response:
    return request("DELETE", url, step=step, headers=headers, throw=throw)


def put(url: str, step: str = None, json=None, headers=None, throw=True) -> requests.Response:
    return request("PUT", url, step=step, json=json, headers=headers, throw=throw)
