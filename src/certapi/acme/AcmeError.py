import re
import requests
from certapi.errors import CertApiException


class AcmeError(CertApiException):
    def __init__(self, message, detail, step):
        super().__init__(message, detail, step)
        self.can_retry = False


class AcmeNetworkError(AcmeError, requests.RequestException):
    """
    There was an error connecting/communicating with the AcmeServer.
    """

    def __init__(self, request: requests.Request, message, detail, step):
        # Initialize both parent classes
        requests.RequestException.__init__(self, request=request)
        AcmeError.__init__(self, message, detail, step)
        self.can_retry = True


class AcmeHttpError(AcmeError, requests.HTTPError):
    """
    Acme Server replied with error status.
    """

    def __init__(self, response: requests.Response, step: str):
        requests.HTTPError.__init__(self, response=response)
        self.response = response
        (message, detail) = self.extract_acme_response_error()
        AcmeError.__init__(self, message, detail, step)

    def extract_acme_response_error(self):
        message = None
        error = None
        try:
            res_json = self.response.json()
            if res_json["status"] == "invalid":
                if res_json["challenges"]:
                    failed_challenge: dict = [x for x in res_json["challenges"] if x["status"] == "invalid"][0]
                    error = failed_challenge["error"]
                    err_detail: str = error.get("detail")
                    err_type: str = error.get("type")
                    validation_record: dict = failed_challenge.get("validationRecord")
                    error = {
                        "url": failed_challenge["url"],
                    }
                    if validation_record is None:
                        # Search for the pattern and extract the content
                        if err_detail.startswith("DNS problem: NXDOMAIN"):
                            error["dns"] = {"error": "DNS record doesn't exist"}
                            error["hostname"] = re.findall(r"looking up [A-Z]+ for ([\w.-]+)", err_detail)[0]
                            message = error["hostname"] + " doesn't have a valid DNS record"
                        elif err_detail:
                            error["dns"] = {"error": err_detail}
                            message = err_detail
                        else:
                            error["dns"] = {"error": error}
                            message = err_detail
                    else:
                        validation_record = validation_record[0]
                        error["hostname"] = validation_record["hostname"]
                        error["dns"] = {
                            "resolved": validation_record["addressesResolved"],
                            "used": validation_record["addressUsed"],
                        }
                        if err_type == "urn:ietf:params:acme:error:connection":
                            if "Timeout during connect" in err_detail:
                                error["connect"] = {"error": "Timeout"}
                                message = (
                                    error["hostname"]
                                    + "["
                                    + validation_record["addressUsed"]
                                    + ":"
                                    + validation_record["port"]
                                    + "] Connect Timeout (Maybe firewall reasons)"
                                )
                            elif err_detail.endswith("Connection refused"):
                                error["connect"] = {"error": "connection refused"}
                                message = (
                                    error["hostname"]
                                    + "["
                                    + validation_record["addressUsed"]
                                    + ":"
                                    + validation_record["port"]
                                    + "] Connection Refused (Is http server running?)"
                                )
                            elif err_detail:
                                message = err_detail
                            else:
                                message = error
                        elif err_detail:
                            pattern = r'Invalid response from .*?: "(.*)"'

                            match = re.search(pattern, err_detail)

                            if match:
                                error["response"] = (match.group(1) if match is not None else err_detail,)
                                error["status_code"] = (error["status"],)
                                message = (
                                    error["hostname"]
                                    + " Status="
                                    + error["status"]
                                    + ": Invalid response in challenge url"
                                )
                            else:
                                message = err_detail
                        else:
                            message = error

            if message is None:
                if res_json.get("detail"):
                    message = res_json["detail"]
                else:
                    message = "Received status=" + str(self.response.status_code) + " from AMCE server"
            if error is None:
                error = res_json

            return (message, error)

        except requests.RequestException as e:
            message = "Received status=" + str(self.response.status_code) + " from AMCE server"
            error = {"url": self.response.request.url, "response": self.response.text}
            return (message, error)


class AcmeInvaliOrderError(AcmeHttpError):
    def __init__(self, response: requests.Response, step: str):
        super().__init__(response, step)


class AcmeInvaliNonceError(AcmeHttpError):
    def __init__(self, response: requests.Response, step: str):
        super().__init__(response, step)
        self.can_retry = True
