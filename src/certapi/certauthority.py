from typing import List, Union, Callable, Tuple, Dict
import json
import time

import requests
from cryptography.x509 import Certificate
from requests import Response

from typing import List, Union, Callable, Tuple, Dict
import json
import time

import requests
from cryptography.x509 import Certificate
from requests import Response

from . import Acme, Challenge, Order
from . import crypto
from . import challenge
from .crypto import cert_to_pem, key_to_pem, digest_sha256
from .crypto_classes import Key
from .db import KeyStore
from .util import b64_string


class CertAuthority:
    def __init__(
        self,
        challenge_store: challenge.ChallengeStore,
        key_store: KeyStore,
        acme_url=None,
        dns_stores: List[challenge.ChallengeStore] = None,
        self_verify_challenge=False,
    ):
        self.acme = Acme(key_store.account_key, url=acme_url)
        self.key_store = key_store
        self.challengesStore: challenge.ChallengeStore = challenge_store
        self.dns_stores = dns_stores if dns_stores is not None else []
        self.self_verify_challenge = self_verify_challenge

    def setup(self):
        self.acme.setup()
        res: Response = self.acme.register()
        if res.status_code == 201:
            print("Acme Account was already registered")
        elif res.status_code != 200:
            raise Exception("Acme registration didn't return 200 or 201 ", res.json())

    def obtainCert(self, host: Union[str, List[str]]) -> "CertificateResponse":
        if type(host) == str:
            host = [host]

        existing = {c[0]: c[1] for c in [(h, self.key_store.get_cert(h)) for h in host] if c[1] is not None}
        missing = [h for h in host if h not in existing]
        if len(missing) > 0:
            has_wildcard = False
            # Determine which challenge store to use
            challenge_store_to_use = self.challengesStore
            for h in missing:
                if h.startswith("*."):  # Wildcard domain
                    has_wildcard = True
                    found_dns_store = False

                    for dns_store in self.dns_stores:
                        if dns_store.has_domain(h.lstrip("*.")):  # Check if the DNS store can handle the base domain
                            challenge_store_to_use = dns_store
                            found_dns_store = True
                            break
                    if not found_dns_store:
                        raise Exception(f"No DNS challenge store found for wildcard domain {h}")
                    break  # Assuming all domains in a single request will use the same challenge type

            private_key = crypto.gen_key_secp256r1()
            order = self.acme.create_authorized_order(missing)

            challenges = order.remaining_challenges()

            for c in challenges:
                print("[ Challenge ]", c.token, "=", c.authorization_key)
                # For DNS-01 challenges, the key should be _acme-challenge.<domain>
                challenge_name = f"_acme-challenge.{c.domain}" if has_wildcard else c.token

                # For DNS-01 challenges, the value is the SHA256 hash of the authorization_key, base64url encoded
                challenge_value = (
                    b64_string(digest_sha256(c.authorization_key.encode("utf8")))
                    if has_wildcard
                    else c.authorization_key
                )

                challenge_store_to_use.save_challenge(challenge_name, challenge_value, c.domain)

            # Add an initial sleep to allow DNS propagation
            if has_wildcard:
                print("Waiting for DNS propagation (10 seconds)...")
                time.sleep(10)

            for c in challenges:
                if self.self_verify_challenge and not has_wildcard:
                    c.self_verify()
                c.verify(dns=has_wildcard)
            end = time.time() + 60  # Increase overall timeout
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
            csr = crypto.create_csr(private_key, missing[0], missing[1:])
            order.finalize(csr)

            def obtain_cert(count=5):
                time.sleep(3)
                order.refresh()  # is this refresh necessary?

                if order.status == "valid":
                    fullchain_cert,certificate =  order.get_certificate()
                    key_id = self.key_store.save_key(private_key, missing[0])
                    cert_id = self.key_store.save_cert(key_id, certificate, missing)
                    issued_cert = IssuedCert(key_to_pem(private_key), fullchain_cert, missing)
                    # Clean up challenges after successful certificate issuance
                    for c in challenges:
                        challenge_name = f"_acme-challenge.{c.domain}" if has_wildcard else c.token
                        challenge_store_to_use.delete_challenge(challenge_name, c.domain)
                    return createExistingResponse(existing, [issued_cert])
                elif order.status == "processing":
                    if count == 0:
                        # Clean up challenges if timeout occurs
                        for c in challenges:
                            challenge_name = f"_acme-challenge.{c.domain}" if has_wildcard else c.token
                            challenge_store_to_use.delete_challenge(challenge_name, c.domain)
                        return None
                    return obtain_cert()
                return None

            return obtain_cert()
        else:
            return createExistingResponse(existing, [])


def createExistingResponse(existing: Dict[str, Tuple[int | str, Key, List[Certificate] | str]], issued_certs: List["IssuedCert"]):
    certs = []
    certMap = {}

    for h, (id, key, cert) in existing.items():
        if id in certMap:
            certMap[id][0].append(h)
        else:
            if isinstance(cert, str):
                cert_pem = cert
            elif isinstance(cert, list):
                cert_pem = certs_to_pem(cert).decode("utf-8")
            else:
                cert_pem = cert_to_pem(cert).decode("utf-8")
            
            certMap[id] = (
                [h],
                key.to_pem().decode("utf-8"),
                cert_pem,
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
    def __init__(self, key: str | Key, cert: str | Certificate | List[Certificate], domains: [str]):
        if isinstance(key, Key):
            key = key.to_pem().decode("utf-8")
        elif isinstance(key, bytes):
            key = key.decode("utf-8")
        
        if isinstance(cert, list):
            cert = certs_to_pem(cert).decode("utf-8")
        elif isinstance(cert, Certificate):
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
