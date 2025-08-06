from certapi.crypto import ECDSAKey, Ed25519Key, RSAKey,Key
from .abstract_certissuer import CertIssuer
from cryptography import x509
from cryptography.x509 import Certificate
from typing import List, Literal, Union, Callable, Tuple, Dict, Optional
import time
from requests import Response
from certapi.acme import Acme,Challenge, Order
from certapi.challenge_store import ChallengeStore


class AcmeCertIssuer(CertIssuer):
    def __init__(
        self,
        account_key: Key,
        challenge_store: ChallengeStore,
        acme_url=None,
        self_verify_challenge=False, # This never needs to be set to True
    ):
        self.acme = Acme(account_key, url=acme_url)
        self.challenge_store = challenge_store
        self.self_verify_challenge = self_verify_challenge

    def setup(self):
        self.acme.setup()
        res: Response = self.acme.register()
        if res.status_code == 201:
            print("Acme Account was already registered")
        elif res.status_code != 200:
            raise Exception("Acme registration didn't return 200 or 201 ", res.json())

    def sign_csr(self, csr: x509.CertificateSigningRequest,challenge_store:ChallengeStore=None,expiry_days: int = 90) -> str:
        challenge_store = challenge_store if challenge_store is not None else self.challenge_store
        hosts = self.get_csr_hostnames(csr)
        order: Order = self.acme.create_authorized_order(hosts)
        challenges = order.remaining_challenges()

        for c in challenges:
            key, value = c.as_key_value()
            challenge_store.save_challenge(key, value, c.domain)
        for c in challenges:
            if self.self_verify_challenge:
                c.self_verify()
        end = time.time() + max(len(challenges) * 10,300)
        remaining_now: List[Challenge] = [x for x in challenges]
        next_remaining = []
        counter = 1

        while len(remaining_now) > 0:
            if time.time() > end and counter > 4:
                print("Order finalization time out")
                break
            for c in remaining_now:
                status = c.query_progress()
                if status != True:  # NOTE that it must be True strictly
                    next_remaining.append(c)
            if len(next_remaining) > 0:
                time.sleep(3)
            remaining_now, next_remaining, counter = next_remaining, [], counter + 1
        order.finalize(csr)

        def obtain_cert(count=5):
            time.sleep(3)
            order.refresh()  # is this refresh necessary?

            if order.status == "valid":
                for c in challenges:
                    challenge_store.delete_challenge(key, c.domain)
                return order.get_certificate()
            elif order.status == "processing":
                if count == 0:
                    # Clean up challenges if timeout occurs
                    for c in challenges:
                        challenge_store.delete_challenge(key, c.domain)
                    return None
                return obtain_cert()
            return None
        return obtain_cert()

    def generate_key_and_cert_for_domains(self, hosts: Union[str, List[str]],
                                   key_type: Literal["rsa","ecdsa","ed25519"] = "rsa",
        expiry_days: int = 90,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        user_id: Optional[str] = None,
        challenge_store: Optional[ChallengeStore] = None):
        if len(hosts) ==0:
            raise ValueError("CertIssuer.generate_key_and_cert_for_domains: empty hosts array provided")
        return self.generate_key_and_cert(hosts[0],hosts[0:],key_type,expiry_days,country,state,locality,organization,user_id,challenge_store)

    
    def generate_key_and_cert_for_domain(self, host:str,
                                  key_type: Literal["rsa","ecdsa","ed25519"] = "rsa",
        expiry_days: int = 90,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        user_id: Optional[str] = None,
        challenge_store: Optional[ChallengeStore] = None):

        return self.generate_key_and_cert(host,[],key_type,expiry_days,country,state,locality,organization,user_id,challenge_store)
    

    def generate_key_and_cert(
        self,
        domain: str,
        alt_names: List[str] = (),
        key_type: Literal["rsa","ecdsa","ed25519"] = "ecdsa",
        expiry_days: int = 90,
        country: Optional[str] = None,
        state: Optional[str] = None,
        locality: Optional[str] = None,
        organization: Optional[str] = None,
        user_id: Optional[str] = None,
        challenge_store: Optional[ChallengeStore] = None,
    ) -> tuple:
        """Create a new certificate with a generated key."""
        # Generate new key based on key_type
        if key_type == "rsa":
            new_key = RSAKey.generate()
        elif key_type == "ecdsa":
            new_key = ECDSAKey.generate()
        elif key_type == "ed25519":
            new_key = Ed25519Key.generate()
        else:
            raise ValueError("Unsupported key type. Use 'rsa' or 'ecdsa'")

        # Create CSR using the new key
        csr = new_key.create_csr(
            domain=domain,
            alt_names=alt_names,
            country=country,
            state=state,
            locality=locality,
            organization=organization,
            user_id=user_id or domain,
        )

        # Sign the CSR to get the certificate
        cert = self.sign_csr(csr, expiry_days=expiry_days, challenge_store=challenge_store)

        return new_key, cert
