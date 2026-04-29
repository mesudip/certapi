Developer Guide
==============

Using CertApi as a Library
--------------------------

The library supports both low-level ACME operations and a higher-level manager that handles
storage and renewals. Pick the approach that fits your integration needs.

1.&nbsp; Low-Level API: Certificate with Cloudflare
------------------------------------------

```python
import json
from certapi import CertApiException, CloudflareChallengeSolver, Key, AcmeCertIssuer


# Initialize the Cloudflare challenge solver
# The API key is read from the CLOUDFLARE_API_KEY environment variable, or you can set it below.
challenge_solver = CloudflareChallengeSolver(api_key=None)

# Initialize cert issuer with a new account key
cert_issuer = AcmeCertIssuer(Key.generate("ecdsa"), challenge_solver)

# Perform setup i.e. fetching directory and registering ACME account
cert_issuer.setup()

try:
	# Obtain a certificate for your domain
	(key, cert) = cert_issuer.generate_key_and_cert_for_domain("your-domain.com")

	print("------ Private Key -----")
	print(key.to_pem())
	print("------- Certificate ------")
	print(cert)
except CertApiException as e:
	print("An error occurred:", json.dumps(e.json_obj(), indent=2))
```

2.&nbsp; High-Level API: AcmeCertManager
-------------------------------

The `AcmeCertManager` provides a high-level interface that handles certificate storage,
automatic renewal checks, and multi-solver management.

```python
from certapi import (
	AcmeCertManager,
	FileSystemKeyStore,
	AcmeCertIssuer,
	CloudflareChallengeSolver,
)

# 1. Setup KeyStore to persist keys and certificates
key_store = FileSystemKeyStore("db")


# DNS-01 via Cloudflare (e.g. for wildcard certs or internal domains)
dns_solver = CloudflareChallengeSolver(api_key="your-cloudflare-token")

# 3. Initialize and Setup AcmeCertManager
# Create cert issuer with the default challenge solver
cert_issuer = AcmeCertIssuer.with_keystore(key_store, dns_solver)

cert_manager = AcmeCertManager(
	key_store=key_store,
	cert_issuer=cert_issuer,
	challenge_solvers=[dns_solver],  # other solvers can be used
)
cert_manager.setup()

# 4. Issue or Reuse Certificate
# Automatically checks and saves to keystore. Renews only if necessary.
response = cert_manager.issue_certificate(["example.com", "www.example.com"])

for cert_data in response.issued:
	print(f"Newly issued for: {cert_data.domains}")
	print(cert_data.cert)

for cert_data in response.existing:
	print(f"Reusing existing for: {cert_data.domains}")
```

3.&nbsp; RenewalManager Integration Contract
-------------------------------------------

`RenewalManager` is the long-running renewal engine for applications that have a changing set
of domains, such as reverse proxies or service discovery controllers.

The architecture has one explicit entry point for domain state:

- The embedding application owns domain discovery and configuration rendering.
- The application publishes the complete desired domain set with
  `RenewalManager.update_watch_domains(domains)` whenever that external state changes.
- `update_watch_domains()` replaces the watch set, prunes cache/backoff state for removed
  domains, and synchronously obtains or renews certificates that are missing or inside the
  configured renewal window.
- The background renewal cycle does not mutate domain state or issue certificates directly
  when a `renewal_callback` is configured. It only invokes that callback.
- The callback is responsible for recomputing the current external domain state and calling
  `update_watch_domains(domains)`.
- `RenewalManager` owns the locking around callback triggers and renewal work, so concurrent
  external updates and background triggers do not run overlapping certificate requests.
- If the application needs side effects after certificates change, such as re-rendering or
  reloading a proxy, that belongs in the application-level flow that called
  `update_watch_domains()` or in an explicit post-renewal callback added for that purpose.

This keeps responsibilities clear: certapi decides *when* renewal should be checked, the
embedding application decides *what domains currently exist*, and `update_watch_domains()`
performs the actual due renewal work for that domain set.

Example:

```python
from certapi.client import RenewalManager


def on_proxy_config_changed(hosts):
	domains = sorted({host.name for host in hosts if host.uses_tls})
	renewal_manager.update_watch_domains(domains)
	# Application-specific reload/rendering belongs here, not inside RenewalManager.


def refresh_proxy_domains():
	hosts = proxy_config.current_hosts()
	on_proxy_config_changed(hosts)


renewal_manager = RenewalManager(cert_manager, renewal_callback=refresh_proxy_domains)
renewal_manager.start()
```
