#!/usr/bin/env python3
from src.certmanager.crypto import create_csr, gen_key_ed25519, csr_to_pem

domain_key = gen_key_ed25519(2048)
csr = create_csr(domain_key, "host8.hosts.sireto.dev")
with open("test.csr", "wb") as f:
    f.write(csr_to_pem(csr))
