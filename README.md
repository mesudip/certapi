# CertApi

CertApi is a Python package for requesting SSL certificates from ACME.
This is to be used as a base library for building other tools, or to integrate Certificate creation feature in you app.

> ⚠️ Warning: This project is in beta. Please stay tuned for the LTS `v1.0.0` release.

## Installation

You can install CertApi using pip

```bash
pip install certapi
```

## Use Low level API

```python
import json
import os
from certapi import FileSystemKeyStore, CertApiException, CloudflareChallengeSolver, AcmeCertManager, AcmeCertIssuer


# Initialize the key store and create acme account key
key_store = FileSystemKeyStore("data")

acme_key = key_store._get_or_generate_key("acme_account", "rsa")[0]

# Initialize the Cloudflare challenge solver
# The API key is read from the CLOUDFLARE_API_KEY environment variable, or you can set it below.
challenge_solver = CloudflareChallengeSolver(api_key=None)

## initialize cert issuer
cert_issuer = AcmeCertIssuer(acme_key, challenge_solver)

# Setup ACME account.
cert_issuer.setup()

try:
    # Obtain a certificate for your domain
    (key, cert) = cert_issuer.generate_key_and_cert_for_domain("your-domain.com")

    print("------ Private Key -----")
    print(key.to_pem())
    print("------- Certificate ------")
    print(cert)
except CertApiException as e:
    print(f"An error occurred:", json.dumps(e.json_obj(), indent=2))

```
