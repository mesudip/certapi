import json
from typing import Literal, Union

import requests

from certapi.util import b64_encode, b64_string
from certapi.crypto import digest_sha256
from .AcmeError import *
from .http import post, get


class Challenge:
    def __init__(self, auth_url, data, acme):
        self._auth_url = auth_url
        self._acme = acme
        self._data = data
        challenge = self.get_challenge()
        self.token: str = challenge["token"]
        self.verified = challenge["status"] == "valid"
        self.domain = data["identifier"]["value"]  # Add domain attribute

        jwk_json = json.dumps(self._acme.jwk, sort_keys=True, separators=(",", ":"))
        thumbprint = b64_encode(digest_sha256(jwk_json.encode("utf8")))
        self.authorization_key = "{0}.{1}".format(self.token, thumbprint.decode("utf-8"))

        self.url = "http://{0}/.well-known/acme-challenge/{1}".format(data["identifier"]["value"], self.token)

    def as_key_value(self, type: Literal["http-01", "dns-01", "tls-alpn-01"] = None):
        challenge = self.get_challenge(type)

        if challenge["type"] == "dns-01":
            key = f"_acme-challenge.{self.domain}"
            value = b64_string(digest_sha256(self.authorization_key.encode("utf8")))
        else:
            key = self.token
            value = self.authorization_key

        return (key, value)

    def verify(self, type: Literal["http-01", "dns-01", "tls-alpn-01"] = None) -> bool:
        if not self.verified:
            response = self._acme._signed_req(
                self.get_challenge(type)["url"], {}, step=f"Verify Challenge [{self.domain}]", throw=False
            )
            if response.status_code == 200 and response.json()["status"] == "valid":
                self.verified = True
                return True
            return False
        return True

    def self_verify(self) -> Union[bool, requests.Response]:
        identifier = self._data["identifier"]
        if identifier["type"] == "dns":
            res = get(f"Self Domain verification [{self.domain}]", self.url)
            if res.status_code == 200 and res.content == self.token.encode():
                return True
            else:
                return res
        return False

    def query_progress(self) -> bool:
        if self.verified:
            return True
        else:
            res = self._acme._signed_req(self._auth_url, step=f"Query Challenge Status [{self.domain}]")
            res_json = res.json()
            if res_json["status"] == "valid":
                self.verified = True
                return True
            elif res_json["status"] == "invalid":
                raise AcmeInvaliOrderError(res, "Query Challenge Status")
            else:
                return False

    def get_challenge(self, type: Literal["http-01", "dns-01", "tls-alpn-01"] = None):
        challenges = self._data["challenges"]
        def_key = type if type is not None else "http-01"
        for method in challenges:
            if method["type"] == def_key:
                return method
        if type is None:
            return challenges[0]

        ch_types = [x["type"] for x in self._data["challenges"]]
        raise AcmeError(
            f"'{type}' not found in challenges for {self.domain}, available: {','.join(ch_types)}",
            {"response": self._data["challenges"]},
            "Query Challenge Status",
        )
