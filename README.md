# CertApi

CertApi is a Python package for requesting SSL certificates from ACME.
This is to be used as a base library for building other tools, or to integrate Certificate creation feature in you app.

> ⚠️ Warning: This project is in beta. Please stay tuned for the LTS `v1.0.0` release.

For a detailed list of changes, please refer to the [CHANGELOG.md](CHANGELOG.md).

## Installation

You can install CertApi using pip

```bash
pip install certapi
```

## Example: Obtain Certificate with Cloudflare

```python
import json
from certapi import CertApiException, CloudflareChallengeSolver, Key, AcmeCertIssuer


# Initialize the Cloudflare challenge solver
# The API key is read from the CLOUDFLARE_API_KEY environment variable, or you can set it below.
challenge_solver = CloudflareChallengeSolver(api_key=None)

## initialize cert issuer with a new account key
cert_issuer = AcmeCertIssuer(Key.generate('rsa'), challenge_solver)

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


## Example: Use High Leve API

```
```
