# CertApi

CertApi is a Python package for requesting SSL certificates from ACME.
This is supposed to be used as a base library for building other tools, or to integrate Certificate creation feature in you app.

## Installation

You can install CertApi using pip:

```bash
pip install certapi
```

## Example Usage

```python
import json
from certapi import FileSystemChallengeStore, FilesystemKeyStore, CertAuthority

key_store = FilesystemKeyStore("data")
challenge_store = FileSystemChallengeStore("./acme-challenges")  # this should be where your web server hosts the .well-known/acme-challenges.

certAuthority = CertAuthority(challenge_store, key_store)
certAuthority.setup()

(response,_) = certAuthority.obtainCert("example.com")

json.dumps(response.__json__(),indent=2)

```
