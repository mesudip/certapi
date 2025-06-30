import os
import re
import threading
import time
from typing import Union, List, Tuple
import json
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import CertificateSigningRequest, Certificate
from . import crypto
import requests
from .crypto import sign, digest_sha256, csr_to_der, jwk, get_algorithm_name, sign_for_jws
from .util import b64_encode, b64_string

acme_url = os.environ.get("LETSENCRYPT_API", "https://acme-staging-v02.api.letsencrypt.org/directory")
# acme_url = os.environ.get("LETSENCRYPT_API", None)


class AcmeError(Exception):
    def __init__(self, message, detail, step):
        super().__init__(step, message)
        self.message: str = message
        self.step: str = step
        self.detail: dict = detail
        self.can_retry = False

    def json_obj(self) -> dict:
        return {"message": self.message, "step": self.step, "detail": self.detail}


class AcmeNetworkError(AcmeError, requests.RequestException):
    """
    There was an error connecting/communicating with the AcmeServer.
    """

    def __init__(self, request: requests.Request, message, detail, step):
        # Initialize both parent classes
        requests.RequestException.__init__(self, request=request)
        AcmeError.__init__(self, message, detail, step)
        requests.RequestException.__init__(self, request=request)  # Pass message to RequestException
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
                        if error["type"] == "urn:ietf:params:acme:error:connection":
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
                            message=error

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


class Acme:

    URL_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
    URL_PROD = "https://acme-v02.api.letsencrypt.org/directory"

    def __init__(self, account_key: Union[RSAPrivateKey, EllipticCurvePrivateKey], url=acme_url):
        self.account_key = account_key
        # json web key format for public key
        self.jwk = jwk(self.account_key)
        print(self.jwk)
        self.nonce = []
        self.acme_url = url if url else self.URL_STAGING
        self.key_id = None
        self.directory = None
        self._nonce_lock = threading.Lock()  # Mutex for safe access to nonce

    def setup(self):
        if self.directory is None:
            self.directory = get("Fetch Acme Directory", self.acme_url).json()

    def _directory(self, key):
        if not self.directory:
            self.directory = get("Fetch Acme Directory", self.acme_url).json()
        return self.directory[key]

    def _directory_req(self, path_name, payload, depth=0):
        url = self._directory(path_name)
        return self._signed_req(url, payload, depth, step="Acme request:" + path_name)

    def get_nonce(self, step: str, counter=1):
        nonce = None
        with self._nonce_lock:  # Acquire nonce
            if self.nonce:
                nonce = self.nonce.pop(0)
        return (
            nonce
            if nonce
            else get(
                step + " > Fetch new Nonce" if step else "Fetch new Nonce from Acme", self._directory("newNonce")
            ).headers.get("Replay-Nonce")
        )

    def record_nonce(self, response: requests.Response) -> requests.Response:
        with self._nonce_lock:
            self.nonce.append(response.headers.get("Replay-Nonce", None))
        return response

    def _signed_req(
        self, url, payload: Union[str, dict, list, bytes, None] = None, depth=0, step="Acme Request", throw=True
    ) -> requests.Response:
        payload64 = b64_encode(payload) if payload is not None else b""

        protected = {
            "url": url,
            "alg": get_algorithm_name(self.account_key),
            "nonce": self.get_nonce(step),
        }

        if self.key_id:
            protected["kid"] = self.key_id
        else:
            protected["jwk"] = self.jwk
        protectedb64 = b64_encode(protected)
        payload = {
            "protected": protectedb64.decode("utf-8"),
            "payload": payload64.decode("utf-8"),
            "signature": b64_string(sign_for_jws(self.account_key, b".".join([protectedb64, payload64]))),
        }
        try:

            response = post(step, url, json=payload, headers={"Content-Type": "application/jose+json"}, throw=throw)
        except AcmeError as e:
            if e.can_retry and depth <= 0:
                time.sleep(2)
                return self._signed_req(url, payload, depth + 1, step, throw)
            else:
                raise e

        return self.record_nonce(response)

    def register(self):
        response = self._directory_req("newAccount", {"termsOfServiceAgreed": True})
        if "location" in response.headers:
            self.key_id = response.headers["location"]
        return response

    def create_authorized_order(self, domains: List[str]) -> "Order":
        payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
        res = self._directory_req("newOrder", payload)
        res_json = res.json()
        challenges = []
        for auth_url in res_json["authorizations"]:
            auth_res = self._signed_req(auth_url, None, step="Authorize Created Order")
            challenges.append(Challenge(auth_url, auth_res.json(), self))
        return Order(res.headers["location"], res_json, challenges, self)

    def authorize_order(self, auth_url):
        return self._signed_req(auth_url, None, step="Authorize Created Order")

    def verify_challenge(self, challenge_url):
        return self._signed_req(challenge_url, {}, step="Verify Challenge")

    def finalize_order(self):
        pass


class Order:
    def __init__(self, url, data, challenges, acme):
        self.url = url
        self._data = data
        self.all_challenges = challenges
        self._acme = acme
        self.status = "pending"

    def remaining_challenges(self) -> List["Challenge"]:
        return [x for x in self.all_challenges if not x.verified]

    def refresh(self):
        response = get("Fetch order Status", self.url)
        self._data = response.json()
        self.status = self._data["status"]
        return response

    def get_certificate(self) -> Tuple[str, List[Certificate]]:
        if self.status == "processing":
            raise ValueError(
                "Order is still in 'processing' state! Wait until the order is finalized, and  call `Order.refresh()`  to update the state"
            )
        elif self.status != "valid":
            raise ValueError("Order not in 'valid' state! Complete challenge and call finalize()")

        certificate_res = self._acme._signed_req(
            self._data["certificate"], step="Get Certificate from Successful Order"
        )
        certificate = crypto.x509.load_pem_x509_certificates(certificate_res.content)
        return ( certificate_res.content, certificate)

    def finalize(self, csr: CertificateSigningRequest):
        """
        :param csr: Private key for the
        """
        finalized = self._acme._signed_req(
            self._data["finalize"], {"csr": b64_string(csr_to_der(csr))}, step="Order Finalize"
        )
        finalized_json = finalized.json()
        self._data = finalized_json
        self.status = finalized_json["status"]


class Challenge:
    def __init__(self, auth_url, data, acme):
        self._auth_url = auth_url
        self._acme = acme
        self._data = data
        challenge = self.get_challenge()
        self.token = challenge["token"]
        self.verified = challenge["status"] == "valid"
        self.domain = data["identifier"]["value"]  # Add domain attribute

        jwk_json = json.dumps(self._acme.jwk, sort_keys=True, separators=(",", ":"))
        thumbprint = b64_encode(digest_sha256(jwk_json.encode("utf8")))
        self.authorization_key = "{0}.{1}".format(self.token, thumbprint.decode("utf-8"))

        self.url = "http://{0}/.well-known/acme-challenge/{1}".format(data["identifier"]["value"], self.token)

    def verify(self, dns=False) -> bool:
        if not self.verified:
            response = self._acme._signed_req(
                self.get_challenge(key="dns-01" if dns else "http-01")["url"], {}, step="Verify Challenge", throw=False
            )
            if response.status_code == 200 and response.json()["status"] == "valid":
                self.verified = True
                return True
            return False
        return True

    def self_verify(self) -> Union[bool, requests.Response]:
        identifier = self._data["identifier"]
        if identifier["type"] == "dns":
            res = get("Self Domain verification", self.url)
            if res.status_code == 200 and res.content == self.token.encode():
                return True
            else:
                return res
        return False

    def query_progress(self) -> bool:
        if self.verified:
            return True
        else:
            res = self._acme._signed_req(self._auth_url, step="Acme Challenge Verification")
            res_json = res.json()
            if res_json["status"] == "valid":
                self.verified = True
                return True
            elif res_json["status"] == "invalid":
                raise AcmeInvaliOrderError(res, "Acme Challenge Verification")
            else:
                return False

    def get_challenge(self, key="http-01"):
        challenges = self._data["challenges"]
        for method in challenges:
            if method["type"] == key:
                return method
        if len(challenges) == 1:
            return challenges[0]

        ch_types = [x["type"] for x in self._data["challenges"]]
        raise AcmeError(
            f"'{key}' not found in challenges. available:{str(ch_types)}",
            {"response": self._data["challenges"]},
            "Acme Challenge Verification",
        )
