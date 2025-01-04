from typing import List, Union, Callable, Tuple, Dict
import json
import time

import requests
from cryptography.x509 import Certificate
from requests import Response

from . import Acme, Challenge, Order
from . import crypto
from . import challenge
from .crypto import cert_to_pem, key_to_pem
from .crypto_classes import Key
from .db import KeyStore


class CertAuthority:
    def __init__(self, challenge_store: challenge.ChallengeStore, key_store: KeyStore,acme_url=None):
        self.acme = Acme(key_store.account_key,url=acme_url)
        self.key_store = key_store
        self.challengesStore: challenge.ChallengeStore = challenge_store

    def setup(self):
        self.acme.setup()
        res: Response = self.acme.register()
        if res.status_code == 201:
            print("Acme Account was already registered")
        elif res.status_code != 200:
            raise Exception("Acme registration didn't return 200 or 201 ", res.json())

    def obtainCert(
        self, host: Union[str, List[str]]
    ) -> Union[Tuple["CertificateResponse", None], Tuple[None, requests.Response]]:
        if type(host) == str:
            host = [host]

        existing = {c[0]: c[1] for c in [(h, self.key_store.get_cert(h)) for h in host] if c[1] is not None}
        missing = [h for h in host if h not in existing]
        if len(missing) > 0:
            private_key = crypto.gen_key_secp256r1()
            order = self.acme.create_authorized_order(missing)

            challenges = order.remaining_challenges()
            for c in challenges:
                print("[ Challenge ]", c.token, "=", c.authorization_key)
                self.challengesStore[c.token] = c.authorization_key
            for c in challenges:
                # c.self_verify()
                c.verify()

            end = time.time() + 40  # max 12 seconds
            source: List[Challenge] = [x for x in challenges]
            sink = []
            counter = 1
            while len(source) > 0:
                if time.time() > end and counter > 4:
                    print("Order finalization time out")
                    break
                for c in source:
                    status = c.query_progress()
                    if status != True:  # NOTE that it must be True strictly
                        sink.append(c)
                if len(sink) > 0:
                    time.sleep(3)
                source, sink, counter = sink, [], counter + 1
            else:
                print("Order is already Ready.")
            csr = crypto.create_csr(private_key, missing[0], missing[1:])
            order.finalize(csr)

            def obtain_cert(count=5):
                time.sleep(3)
                order.refresh()  # is this refresh necessary?

                if order.status == "valid":
                    (certificate, _) = order.get_certificate()
                    key_id = self.key_store.save_key(private_key, missing[0])
                    cert_id = self.key_store.save_cert(key_id, certificate, missing)
                    issued_cert = IssuedCert(key_to_pem(private_key), certificate, missing)
                    response = createExistingResponse(existing, [issued_cert])
                    return (response, None)
                elif order.status == "processing":
                    if count == 0:
                        return None
                    return obtain_cert()
                return None

            return obtain_cert()
        else:
            return createExistingResponse(existing, []), None


def createExistingResponse(existing: Dict[str, Tuple[int | str, Key, Certificate]], issued_certs: List["IssuedCert"]):
    certs = []
    certMap = {}
    for h, (id, key, cert) in existing.items():
        if id in certMap:
            certMap[id][0].append(h)
        else:
            certMap[id] = (
                [h],
                key.to_pem().decode("utf-8"),
                cert_to_pem(cert).decode("utf-8"),
            )
    for hosts, key, cert in certMap.values():
        certs.append(IssuedCert(key, cert, hosts))

    return CertificateResponse(certs, issued_certs)


class CertificateResponse:
    def __init__(self, existing, issued):
        self.existing: List[IssuedCert] = existing
        self.issued: List[IssuedCert] = issued

    def __repr__(self):
        return "CertificateResponse(existing={0},new={1})".format(repr(self.existing), repr(self.issued))

    def __str__(self):
        if self.issued:
            return "(existing: {0},new: {1})".format(str(self.existing), str(self.issued))
        else:
            return "(existing: {0})".format(str(self.existing))

    def __json__(self):
        return {
            "existing": [x.__json__() for x in self.existing],
            "issued": [x.__json__() for x in self.issued],
        }


class IssuedCert:
    def __init__(self, key: str | Key, cert: str | Certificate, domains: [str]):
        if isinstance(key, Key):
            key = key.to_pem().decode("utf-8")
        elif isinstance(key, bytes):
            key = key.decode("utf-8")
        if isinstance(cert, Certificate):
            cert = cert_to_pem(cert).decode("utf-8")
        elif isinstance(cert, bytes):
            cert = cert.decode("utf-8")
        self.privateKey = key
        self.certificate = cert
        self.domains = domains

    def __repr__(self):
        # return "IssuedCert(hosts={0})".format(self.domains)
        return "(hosts: {0}, certificate:{1})".format(self.domains, self.certificate)

    def __str__(self):
        return "(hosts: {0}, certificate:{1})".format(self.domains, self.certificate)

    def __json__(self):
        return {"privateKey": self.privateKey, "certificate": self.certificate, "domains": self.domains}
