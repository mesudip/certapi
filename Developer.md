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

The architecture has one normal entry point for domain state:

- The embedding application owns domain discovery and configuration rendering.
- The application publishes the complete desired domain set with
  `RenewalManager.update_watch_domains(domains)` whenever that external state changes.
- `update_watch_domains()` replaces the watch set, prunes cache/backoff state for removed
  domains, and synchronously obtains or renews certificates that are missing or inside the
  configured renewal window.
- The background worker is only a timer for already-watched certificates. It must not discover
  domains, and it must not call `renewal_callback` just because the worker started or because
  `update_watch_domains()` refreshed the watch set.
- The worker invokes `renewal_callback` only as a trigger when an existing cached watched
  certificate reaches the renewal window, or when an explicit force trigger asks for an
  immediate cycle.
- `renewal_callback` is not the domain update API. It is only a signal to the embedding
  application that its current domain set should be refreshed. The application must then call
  `update_watch_domains(domains)` from its own refresh/reconcile flow.
- `RenewalManager` owns the locking around callback triggers and renewal work, so concurrent
  external updates and background triggers do not run overlapping certificate requests.
- The callback should be small and non-blocking when possible: set an event, enqueue a refresh,
  or wake the application's controller loop. Rendering config, reloading a proxy, notifying
  service discovery, and publishing the new watch set belong to the application-level flow that
  handles that refresh.

This keeps responsibilities clear: certapi decides *when* renewal should be checked, the
embedding application decides *what domains currently exist*, and `update_watch_domains()`
performs the actual due renewal work for that domain set.

Example:

```python
from certapi.client import RenewalManager


def current_tls_domains():
	hosts = proxy_config.current_hosts()
	return sorted({host.name for host in hosts if host.uses_tls})


def publish_current_watch_set():
	renewal_manager.update_watch_domains(current_tls_domains())


def on_proxy_config_changed():
	# External configuration changes are application events, so the app can do
	# its own config rendering/reload flow after publishing the current watch set.
	publish_current_watch_set()
	proxy_config.render()
	proxy.reload()


def request_domain_refresh():
	# RenewalManager calls this only as a trigger for due watched certs or force cycles.
	# The application controller owns the actual refresh and update_watch_domains() call.
	controller.request_domain_refresh()


renewal_manager = RenewalManager(cert_manager, renewal_callback=request_domain_refresh)

# Seed the initial watch set explicitly; start() does not discover domains or invoke the callback.
publish_current_watch_set()
renewal_manager.start()
```
