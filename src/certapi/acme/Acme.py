import os
import re
import threading
import time
from typing import Union, List, Tuple
import json
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import CertificateSigningRequest, Certificate
from certapi.crypto import crypto
import requests
from certapi.crypto import Key
from certapi.crypto.crypto_classes import ECDSAKey, RSAKey
from certapi.util import b64_encode, b64_string
from .AcmeError import *
from .http import *
from .Challenge import Challenge
from .Order import Order


class Acme:

    URL_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
    URL_PROD = "https://acme-v02.api.letsencrypt.org/directory"

    def __init__(self, account_key: Key, url=URL_STAGING):
        self.account_key: Key = account_key

        # json web key format for public key
        self.jwk = account_key.jwk()
        self.alg_name = account_key.algorithm_name()
        print(self.jwk)
        self.nonce = []
        self.acme_url = url if url else os.environ.get("ACME_API_URL", self.URL_STAGING)
        self.key_id = None
        self.directory = None
        self._nonce_lock = threading.Lock()  # Mutex for safe access to nonce

    def setup(self):
        if self.directory is None:
            self.directory = get("Fetch Acme Directory", self.acme_url).json()

    def register(self):
        """
        Register an ACME Account. Re-registering is idempotent.
        """
        response = self._directory_req("newAccount", {"termsOfServiceAgreed": True})
        if "location" in response.headers:
            self.key_id = response.headers["location"]
        return response

    def create_order(self, domains: List[str]) -> "Order":
        """
        Makes newOrder request, fetches all challenge details, and returns an Order object.
        You cann then Use functions in Order and Challenge
        """
        payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
        res = self._directory_req("newOrder", payload)
        res_json = res.json()
        challenges = []
        identifiers = res_json["identifiers"]

        # auth_url means the url for challenge. In case of ACME challenge and authorization means same.
        for auth_url, identifier in zip(res_json["authorizations"], identifiers):
            auth_res = get(f"Get Challenge [{identifier['value']}]", auth_url)
            challenges.append(Challenge(auth_url, auth_res.json(), self))
        return Order(res.headers["location"], res_json, challenges, self)

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
            "alg": self.alg_name,
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
            "signature": b64_string(self.account_key.jws_sign(b".".join([protectedb64, payload64]))),
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
