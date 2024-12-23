import json
import time
from typing import Union, Callable

import requests
from cryptography.x509 import Certificate
from requests import Response

from . import Acme
from . import db
from . import crypto
from . import challenge


# pathlib.Path.mkdir("/var/www/html/.acme/well-known")


class CertAuthority:
    def __init__(self, challengeStore: Callable[[str, str], None] = challenge.addChallenge):
        self.acme = Acme(db.account_key)
        res: Response = self.acme.register()
        if res.status_code == 201:
            print("Acme Account was already registered")
        elif res.status_code != 200:
            raise Exception("Acme registration didn't return 200 or 201 ", res.json())

        self.challengesStore: Callable[[str, str], None] = challengeStore

    def obtainCert(self, host) -> (Union[Certificate, None], requests.Response):
        if type(host) == str:
            host = [host]

        existing = {c[0]: c[1] for c in [(h, db.getCert(h)) for h in host] if c[1] is not None}
        missing = [h for h in host if h not in existing]
        if len(missing) > 0:
            private_key = crypto.gen_key_secp256r1()
            order, (error) = self.acme.create_authorized_order(missing)
            if order is None:
                err: requests.Response = error
                raise ValueError("Unexpected response code :" + str(err.status_code) + json.dumps(err.json(), 2))
            challenges = order.remaining_challenges()
            for c in challenges:
                print("[ Challenge ]", c.token, "=", c.authorization_key)
                self.challengesStore(c.token, c.authorization_key)
                # c.self_verify()
                c.verify()
            end = time.time() + 40  # max 12 seconds
            source = [x for x in challenges]
            sink = []
            counter = 1
            while len(source) > 0:
                if time.time() > end and counter > 4:
                    print("Order finalization time out")
                    break
                for c in source:
                    status, maybe_request = c.query_progress()
                    if not status:  # NOTE that it must be True strictly
                        sink.append(c)
                if len(sink) > 0:
                    time.sleep(3)
                source, sink, counter = sink, [], counter + 1
            else:
                print("Order is alrealdy Ready.")
            csr = crypto.create_csr(private_key, missing[0], missing[1:])
            order.finalize(csr)

            def obtain_cert(count=5):
                time.sleep(3)
                order.refresh()
                if order.status == "valid":
                    (certificate, _) = order.get_certificate()
                    key_id = db.save_key(private_key)
                    cert_id = db.save_cert(key_id, certificate, domains=missing)
                    createExistingResponse(existing)
                    return ((existing, missing, private_key, certificate), None)
                elif order.status == "processing":
                    if count == 0:
                        return None, error
                    return obtain_cert()
                return None, error

            return obtain_cert()
        else:
            return createExistingResponse(existing)


def createExistingResponse(existing):
    certs = []
    certMap = {}
    for h, (id, key, cert) in existing.items():
        if id in certMap:
            certMap[id][0].append(h)
        else:
            certMap[id] = (
                [h],
                crypto.key_to_pem(crypto.key_from_der(key)).decode("utf-8"),
                crypto.cert_to_pem(crypto.cert_from_der(cert)).decode("utf-8"),
            )
    for hosts, key, cert in certMap.values():
        certs.append(IssuedCert(key, cert, hosts))
    return CertificateResponse(certs, [])


class CertificateResponse:
    def __init__(self, existing, issued):
        self.certs = existing
        self.issued = issued

    def __repr__(self):
        return "CertificateResponse(existing={0},new={1})".format(repr(self.existing), repr(self.issued))

    def __str__(self):
        if self.issued:
            return "(existing: {0},new: {1})".format(str(self.existing), str(self.issued))
        else:
            return "(existing: {0})".format(str(self.existing))

    def json(self):
        return {
            "existing": self.existing,
            "issued": self.issued,
        }


class IssuedCert:
    def __init__(self, key: str, cert: str, domains: [str]):
        self.privateKey = key
        self.certificate = cert
        self.domains = domains

    def __repr__(self):
        # return "IssuedCert(hosts={0})".format(self.domains)
        return "(hosts: {0}, certificate:{1})".format(self.domains, self.certificate)

    def __str__(self):
        return "(hosts: {0}, certificate:{1})".format(self.domains, self.certificate)

    def json(self):
        return {"privateKey": self.privateKey, "certificate": self.certificate, "domains": self.domains}
