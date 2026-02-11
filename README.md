CertApi
=============================

Certapi talks with DNS provider and ACME to issue SSL certificates and save it to a keystore.

CertApi is a base library for building other tools, or to integrate Certificate creation feature in your app. CertAPI also provides HTTP api server and can be deployed using Docker

[![Build Status](https://github.com/mesudip/certapi/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/mesudip/certapi/actions/workflows/tests.yml)
[![codecov](https://codecov.io/github/mesudip/certapi/graph/badge.svg?token=NYTNCH29IT)](https://codecov.io/github/mesudip/certapi)
[![PyPI version](https://img.shields.io/pypi/v/certapi.svg)](https://pypi.org/project/certapi/)

## Why another library?

I designed this library so that it can be imported and plugged in to other python projects. Goal is not to provide CLIs or quick working demo, but to be versatile for any use case.

- Pluggable keystores for keys and certificates
- Pluggable Challenge solvers for DNS and Http challenge solving
- High-level manager with renewal checks and multi-solver support
- Same interface for working locally, or requesting certificate from certapi server.

See the developer guide in [Developer.md](Developer.md) for library usage and workflows.


## Installation

You can install CertApi using pip

```bash
pip install certapi
```

## CLI

CertApi also ships with a CLI for quick verification and certificate issuance.

```bash
## Crtapi's dependencies are already included in the python installation. This doesn't affect the system.
sudo python3 -m pip  install certapi --break-system-packages 
 
# Use Cloudflare DNS-01 by providing API key or token
export CLOUDFLARE_API_KEY="..."  
sudo certapi obtain example.com


# If you have already setup DNS.
sudo certapi verify example.com  # Check that the DNS is setup correctly
sudo certapi obtain example.com

```