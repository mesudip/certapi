CertApi
=============================

Certapi talks with DNS provider and ACME to issue SSL certificates and save it to a keystore.

CertApi is a base library for building other tools, or to integrate Certificate creation feature in your app. CertAPI also provides HTTP api server and can be deployed using Docker

[![Build Status](https://github.com/mesudip/certapi/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/mesudip/certapi/actions/workflows/tests.yml)
[![codecov](https://codecov.io/github/mesudip/certapi/graph/badge.svg?token=NYTNCH29IT)](https://codecov.io/github/mesudip/certapi)
[![PyPI version](https://img.shields.io/pypi/v/certapi.svg)](https://pypi.org/project/certapi/)



## Installation

You can install CertApi using pip

```bash
pip install certapi
```

## Example: Low Leve API : Certificate with Cloudflare

```python
import json
from certapi import CertApiException, CloudflareChallengeSolver, Key, AcmeCertIssuer


# Initialize the Cloudflare challenge solver
# The API key is read from the CLOUDFLARE_API_KEY environment variable, or you can set it below.
challenge_solver = CloudflareChallengeSolver(api_key=None)

## initialize cert issuer with a new account key
cert_issuer = AcmeCertIssuer(Key.generate('ecdsa'), challenge_solver)

# Preform setup i.e. fetching directory and registering ACME account
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


## Example: High Level API (with AcmeCertManager)

The `AcmeCertManager` provides a high-level interface that handles certificate storage, automatic renewal checks, and multi-solver management.

```python
from certapi import (
    AcmeCertManager, 
    FileSystemKeyStore, 
    AcmeCertIssuer, 
    CloudflareChallengeSolver
)

# 1. Setup KeyStore to persist keys and certificates
key_store = FileSystemKeyStore("db")


# DNS-01 via Cloudflare (e.g. for wildcard certs or internal domains)
dns_solver = CloudflareChallengeSolver(api_token="your-cloudflare-token")

# 3. Initialize and Setup AcmeCertManager
# Create cert issuer with the default challenge solver
cert_issuer = AcmeCertIssuer.with_keystore(key_store, dns_solver)

cert_manager = AcmeCertManager(
    key_store=key_store,
    cert_issuer=cert_issuer,
    challenge_solvers=[dns_solver], # other solvers can be used
    )
cert_manager.setup()

# 4. Issue or Reuse Certificate
# Automatically checks sand saves to keystore. Renews only if necessary.
response = cert_manager.issue_certificate(["example.com", "www.example.com"])

for cert_data in response.issued:
    print(f"Newly issued for: {cert_data.domains}")
    print(cert_data.cert)

for cert_data in response.existing:
    print(f"Reusing existing for: {cert_data.domains}")
```
