import requests


class CertApiException(Exception):
    """
    Base exception for all CertAPI related errors.
    """

    def __init__(self, message: str, detail: dict = None, step: str = None):
        super().__init__(message)
        self.message = message
        self.detail = detail if detail is not None else {}
        self.step = step
        self.can_retry = False

    def json_obj(self) -> dict:
        return {"name": self.__class__.__name__, "message": self.message, "step": self.step, "detail": self.detail}


class NetworkError(CertApiException, requests.RequestException):
    """
    There was an error connecting/communicating with an external service.
    """

    def __init__(self, request: requests.Request, message: str, detail: dict = None, step: str = None):
        requests.RequestException.__init__(self, request=request)
        CertApiException.__init__(self, message, detail, step)
        self.can_retry = True


class HttpError(CertApiException, requests.HTTPError):
    """
    External service replied with an error status.
    """

    def __init__(self, response: requests.Response, message: str, detail: dict = None, step: str = None):
        requests.HTTPError.__init__(self, response=response)
        self.response = response
        CertApiException.__init__(self, message, detail, step)


class DomainNotOwnedException(CertApiException):
    """
    The specified domain is not owned or managed by the configured account.
    """

    def __init__(self, message: str, detail: dict = None, step: str = None):
        super().__init__(message, detail, step)
        self.can_retry = False
