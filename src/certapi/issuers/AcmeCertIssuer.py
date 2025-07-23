from .abstract_certissuer import CertIssuer
from cryptography import x509
from cryptography.x509 import Certificate
from typing import List, Union, Callable, Tuple, Dict
import time
from requests import Response
from certapi.acme import Acme,Challenge
from certapi.challenge import ChallengeStore
from certapi.crypto import cert_to_pem, certs_to_pem, key_to_pem, digest_sha256,Key
from certapi.util import b64_string


class AcmeCertIssuer(CertIssuer):
    def __init__(
        self,
        account_key: Key,
        primary_challenge_store: ChallengeStore,
        dns_stores: List[ChallengeStore] = None,
        acme_url=None,
        self_verify_challenge=False,
    ):
        self.acme = Acme(account_key, url=acme_url)
        self.challengesStore: ChallengeStore = primary_challenge_store
        self.dns_stores :List[ChallengeStore] = dns_stores if dns_stores is not None else []
        self.self_verify_challenge = self_verify_challenge

    def setup(self):
        self.acme.setup()
        res: Response = self.acme.register()
        if res.status_code == 201:
            print("Acme Account was already registered")
        elif res.status_code != 200:
            raise Exception("Acme registration didn't return 200 or 201 ", res.json())
        

    def checkWildcard(self,hosts:List[str]):
        for h in hosts:
            if h.startswith("*."):  # Wildcard domain
                has_wildcard = True
                found_dns_store = False

                for dns_store in self.dns_stores:
                    if dns_store.has_domain(h.lstrip("*.")):  # Check if the DNS store can handle the base domain
                        return dns_store
                        break
                if not found_dns_store:
                    raise Exception(f"No DNS challenge store found for wildcard domain {h}")
                break  # Assuming all domains in a single request will use the same challenge type

    def sign_csr(self, csr:x509.CertificateSigningRequest)-> str:
        hosts = self.get_csr_hostnames(csr)

        if len(hosts) > 0:
            wildcard_store = self.checkWildcard(hosts)
            # Determine which challenge store to use
            challenge_store_to_use =  wildcard_store  if wildcard_store else self.challengesStore
            has_wildcard=wildcard_store is not None
        
            order = self.acme.create_authorized_order(hosts)
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
            order.finalize(csr)

            def obtain_cert(count=5):
                time.sleep(3)
                order.refresh()  # is this refresh necessary?

                if order.status == "valid":
                    for c in challenges:
                        challenge_name = f"_acme-challenge.{c.domain}" if has_wildcard else c.token
                        challenge_store_to_use.delete_challenge(challenge_name, c.domain)
                    return order.get_certificate()    
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

