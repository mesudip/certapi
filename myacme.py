#!/usr/bin/env python3
from src.certmanager.db import account_key
from src.certmanager import CertAuthority
import json


def challengeAdder(k, v):
    with open(".well-known/acme-challenge/" + k, "w") as file:
        file.write(v)


authority = CertAuthority(challengeAdder)
result = authority.obtainCert(["host11.hosts.sireto.dev", "host12.hosts.sireto.dev"])
if result is not None:
    print(result)
