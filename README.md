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

## HTTP domain verification

CertAPI 1.1.17 adds `GET /api/verify?hostname=example.com&hostname=www.example.com` and `CertManagerClient.verify_domains(hosts)`. The server writes a temporary HTTP-01 probe into its filesystem challenge store, fetches each domain's `http://<domain>/.well-known/acme-challenge/<token>` URL without following redirects, and compares the exact payload. The response contains `verified` and `failed` hostname lists. No certificate is obtained or reused; DNS solver support is not treated as HTTP reachability. Invalid hostnames and wildcards fail this HTTP check. A server without a filesystem HTTP solver returns 503.

Reverse proxies must forward the challenge path to this server, including when application routes require authentication, redirect to HTTPS, or return 503. Upgrade the server as well as the client to use this endpoint. A client talking to an older server reports an explicit upgrade error instead of treating API connectivity as domain verification.

Certificate `obtain` calls with `skip_failing=false` reject any domains that fail solver selection before issuing the remaining domains. With `skip_failing=true`, rejected domains appear in the response's `failed` list, so callers can report partial failures and apply renewal backoff.


## Installation

You can install CertApi using pip

```bash
pip install certapi
```

## CLI

CertApi also ships with a CLI for quick verification and certificate issuance.

```bash
## Certapi's dependencies are already included in the python installation. This doesn't affect the system.
sudo python3 -m pip install certapi --break-system-packages
```

### 1. With HTTP Challenge

HTTP challenge requires you to have seup the DNS correctly. The ACME server will verify your domain by making an HTTP request.

```bash
# Verify environment and HTTP routing
sudo certapi verify example.com www.example.com

# Obtain a certificate (requires root for HTTP-01)
sudo certapi obtain example.com www.example.com
```

### 2. With DNS Provider Key

Using DNS-01 challenge with Cloudflare doesn't require the DNS to be setup. Set your Cloudflare API key as an environment variable.

```bash
# Set Cloudflare API key or token
export CLOUDFLARE_API_KEY=...   # or CLOUDFLARE_API_TOKEN

# Verify DNS configuration
sudo certapi verify example.com

# Obtain a certificate using DNS-01
sudo certapi obtain example.com www.example.com
```
