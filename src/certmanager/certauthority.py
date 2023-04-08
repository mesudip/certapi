import time
from typing import Union, Callable

import requests
from cryptography.x509 import Certificate

from certmanager import Acme
from certmanager import db
from certmanager import crypto
import pathlib
from certmanager import challenge


# pathlib.Path.mkdir("/var/www/html/.acme/well-known")

class CertAuthority:
    def __init__(self,challengeStore:Callable[[str,str],None]=challenge.addChallenge):
        self.acme = Acme(db.account_key)
        res=self.acme.register()
        if(res.status_code==201):
            print("Acme Account was already registered")
        self.challengesStore: Callable[[str,str],None] = challengeStore

    def obtainCert(self, host) -> (Union[Certificate,None],requests.Response):
        if type(host) == str:
            host = [host]

        existing = {c[0]: c[1] for c in [(h, db.getCert(h)) for h in host] if c[1] is not None}
        missing = [h for h in host if h not in existing]
        if len(missing) > 0:
            private_key=crypto.gen_key()
            order, error = self.acme.create_authorized_order(missing)
            for c in order.remaining_challenges():
                print ("[ Challenge ]",c.token,'=',c.authorization_key)
                self.challengesStore(c.token,c.authorization_key) 
                #c.self_verify()
                c.verify()
            end = time.time() + 12  # max 12 seconds
            source = [x for x in order.challenges]
            sink = []
            counter = 1
            while len(source) > 0:
                if time.time() > end and counter > 4:
                    break
                for c in source:
                    status, maybe_request = c.query_progress()
                    if not status:  # NOTE that it must be True strictly
                        sink.append(c)
                if len(sink) >0:
                    time.sleep(3)
                source, sink ,counter= sink, [],counter+1

            else:
                print("Order finalization time out")
            csr=crypto.create_csr(private_key,missing[0],missing[1:])
            certificate,error= order.finalize(csr)
            if certificate:
                key_id=db.save_key(private_key)
                cert_id=db.save_cert(key_id,certificate,domains=missing)
                return ((existing,missing,private_key,certificate),None)
            return None,error
        else:
            return ({h:{"private_key":crypto.key_der_to_pem(key).decode('utf-8'),"certificate":crypto.cert_der_to_pem(cert).decode('utf-8') }for h,(id,key,cert) in existing.items() },[],None,None),None
