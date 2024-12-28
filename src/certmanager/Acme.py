import os
from typing import Union, List, Tuple
import json
import requests as req
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import CertificateSigningRequest, Certificate
from . import crypto
import requests
from .crypto import sign, sign_jws, digest_sha256, csr_to_der, jwk, get_algorithm_name
from .util import b64_encode, b64_string

acme_url = os.environ.get("LETSENCRYPT_API", "https://acme-staging-v02.api.letsencrypt.org/directory")


class AcmeError(Exception):
    def __init__(self, message, reason, when):
        self.message = message
        self.when = when
        self.reason = reason

    def jsonObj(self):
        return {"message": self.message, "when": self.when, "reason": self.reason}


class AcmeNetworkError(AcmeError):
    pass


class AcmeHttpError(AcmeError):
    pass


class Acme:
    def __init__(self, account_key: Union[RSAPrivateKey, EllipticCurvePrivateKey], url=acme_url):
        self.account_key = account_key
        # json web key format for public key
        self.jwk = jwk(self.account_key)
        self.nonce = None
        self.key_id = None
        self.directory = requests.get(acme_url).json()

    def _directory(self, key):
        if not self.directory:
            self.directory = req.get(acme_url)
        return self.directory[key]

    def _directory_req(self, path_name, payload, depth=0):
        url = self._directory(path_name)
        return self._signed_req(url, payload, depth)

    def _signed_req(self, url, payload: Union[str, dict, list, bytes, None] = None, depth=0) -> requests.Response:
        orig_payload = payload
        payload64 = b64_encode(payload) if payload is not None else b""
        protected = {
            "url": url,
            "alg": get_algorithm_name(self.account_key),
            "nonce": req.get(self._directory("newNonce")).headers.get("Replay-Nonce"),
        }
        if self.key_id:
            protected["kid"] = self.key_id
        else:
            protected["jwk"] = self.jwk
        protectedb64 = b64_encode(protected)
        payload = {
            "protected": protectedb64.decode("utf-8"),
            "payload": payload64.decode("utf-8"),
            "signature": b64_string(sign(self.account_key, b".".join([protectedb64, payload64]))),
        }

        print("-" * 30 + " Request  " + "-" * 30)
        response = req.post(url, json=payload, headers={"Content-Type": "application/jose+json"})
        print(url)
        if response.status_code != 200:
            print(json.dumps({x[0]: x[1] for x in response.headers.items()}, indent=2))
        print(response.text)
        print("-" * 60)
        self.nonce = response.headers.get("Replay-Nonce", None)
        return response

    def register(self):
        response = self._directory_req("newAccount", {"termsOfServiceAgreed": True})
        if "location" in response.headers:
            self.key_id = response.headers["location"]
        return response

    def create_authorized_order(self, domains: List[str]) -> (Union["Order", None], Union[requests.Response, None]):
        payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
        res = self._directory_req("newOrder", payload)
        if 200 <= res.status_code < 300:
            res_json = res.json()
            challenges = []
            for auth_url in res_json["authorizations"]:
                auth_res = self._signed_req(auth_url, None)
                if 200 <= auth_res.status_code < 300:
                    challenges.append(Challenge(auth_url, auth_res.json(), self))
                else:
                    return None, res
            return Order(res.headers["location"], res_json, challenges, self), None
        else:
            return None, res

    def authorize_order(self, auth_url):
        return self._signed_req(auth_url, None)

    def verify_challenge(self, challenge_url):
        return self._signed_req(challenge_url, {})

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
        response = requests.get(self.url)
        if response.status_code == 200:
            self._data = response.json()
            self.status = self._data["status"]
        return response

    def get_certificate(self) -> Tuple[Union[Certificate, None], Union[requests.Response, None]]:
        if self.status == "processing":
            raise ValueError(
                "Order is still in 'processing' state! Wait until the order is finalized, and  call `Order.refresh()`  to update the state"
            )
        elif self.status != "valid":
            raise ValueError("Order not in 'valid' state! Complete challenge and call finalize()")

        certificate_res = self._acme._signed_req(self._data["certificate"])
        if certificate_res.status_code == 200:
            certificate = crypto.x509.load_pem_x509_certificate(certificate_res.content)
            return certificate, None
        return None, certificate_res

    def finalize(
        self, csr: CertificateSigningRequest
    ) -> Union[Tuple[None, requests.Response], Tuple[Certificate, None]]:
        """
        :param csr: Private key for the
        """
        finalized = self._acme._signed_req(self._data["finalize"], {"csr": b64_string(csr_to_der(csr))})
        finalized_json = finalized.json()
        self._data = finalized_json
        if finalized.status_code == 200:
            self.status = finalized_json["status"]
        return None, finalized


class Challenge:
    def __init__(self, auth_url, data, acme):
        self._auth_url = auth_url
        self._acme = acme
        self._data = data
        challenge = self.get_challenge()
        self.token = challenge["token"]
        self.verified = challenge["status"] == "valid"

        jwk_json = json.dumps(self._acme.jwk, sort_keys=True, separators=(",", ":"))
        thumbprint = b64_encode(digest_sha256(jwk_json.encode("utf8")))
        self.authorization_key = "{0}.{1}".format(self.token, thumbprint.decode("utf-8"))

        self.url = "http://{0}/.well-known/acme-challenge/{1}".format(data["identifier"]["value"], self.token)

    def verify(self) -> bool:
        if not self.verified:
            response = self._acme._signed_req(self.get_challenge()["url"], {})
            if response.status_code == 200 and response.json()["status"] == "valid":
                self.verified = True
                return True
            return False
        return True

    def self_verify(self) -> Union[bool, requests.Response]:
        identifier = self._data["identifier"]
        if identifier["type"] == "dns":
            res = requests.get(self.url)
            if res.status_code == 200 and res.content == self.token.encode():
                return True
            else:
                return res
        return False

    def query_progress(self) -> (bool, Union[None, requests.Response]):
        if self.verified:
            return True, None
        else:
            res = self._acme._signed_req(self._auth_url, None)
            res_json = res.json()
            if res_json["status"] == "valid":
                self.verified = True
                return True, None
            elif res_json["status"] == "invalid":
                failed_challenge = [x for x in res_json["challenges"] if x["status"] == "invalid"][0]
                raise AcmeHttpError(
                    "Order is invalid",
                    "ACME connected to "
                    + failed_challenge["validationRecord"][0]["addressUsed"]
                    + "And got ["
                    + str(failed_challenge["error"]["status"])
                    + "]: "
                    + failed_challenge["error"]["detail"],
                    "challenge status",
                )
            else:
                return None, res

    def get_challenge(self, key="http-01"):
        for method in self._data["challenges"]:
            if method["type"] == key:
                return method
        raise KeyError("'http-01' not found in challenges")
