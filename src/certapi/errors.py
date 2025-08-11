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
        return {
            "message": self.message,
            "step": self.step,
            "detail": self.detail
        }
