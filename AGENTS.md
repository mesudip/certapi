# AGENTS.md

## RenewalManager Architecture

`RenewalManager` does not own domain discovery. Embedding applications such as reverse proxies own the current domain set and publish the complete desired set with `update_watch_domains(domains)` whenever their external configuration changes.

`update_watch_domains(domains)` is the only normal entry point that mutates watched domains. It must synchronously process missing or due certificates for the newly published set, then return with cache/backoff state updated.

The background renewal worker is only a timer for already-watched certificates. It must not call `renewal_callback` just because the worker started or because a watch set was refreshed. It should call `renewal_callback` only when an existing cached watched certificate reaches the renewal window, or when an explicit force trigger asks for an immediate cycle.

`renewal_callback` exists to let the embedding application refresh the watched domain set before certapi renews certificates that may be stale or no longer used. The callback should recompute current domains and call `update_watch_domains(domains)`. It should not perform unrelated application side effects such as proxy reloads.

