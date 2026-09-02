# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
  

## [1.1.15] - 2026-09-02
### Fixed
- Wildcard and concrete domains are no longer sent in the same ACME order. `*.example.com`
  is now issued as its own certificate, which fixes the "invalid request" rejections seen
  when a wildcard was requested alongside names under it.
- DNS-01 challenge cleanup now runs after every issuance attempt, including when challenge
  creation, verification, polling, or order finalization fails. Cleanup is best-effort per
  record so one provider error does not prevent the remaining records from being removed.
  Cloudflare and DigitalOcean also retain every record id when a challenge name has several
  concurrent TXT values instead of losing all but the last id.
- Issuance now skips a failing batch on any `CertApiException`, not just `AcmeError`. DNS solver
  errors (`DomainNotOwnedException`, Cloudflare/DigitalOcean API errors) previously escaped the
  handler and aborted the whole call, discarding certificates already issued in that call and
  leaving the remaining domains unattempted.
- `skip_failing=True` now behaves the same with and without `batch_domains`. It was previously a
  no-op whenever `batch_domains=False` (the default), so a run covering two challenge solvers
  would abort entirely when the first solver failed, never attempting the second.
- `GET /obtain` no longer turns a single failing batch into a 500 that discards the certificates
  that did succeed; it returns them alongside a `failed` entry.
- Domains are normalized (trimmed, lowercased, trailing dot removed) and de-duplicated before
  keystore lookup, DNS-provider ownership checks, issuance, and storage. Previously a host such
  as `API.Example.COM.` could fail provider discovery or be stored under a name that later lookup
  could not find.

### Added
- `CertificateResponse.failed`: a list of `FailedDomains` (`domains`, `name`, `message`, `step`)
  describing batches that could not be issued, populated when `skip_failing=True`. Also present in
  the `GET /obtain` payload. The originating exception's `detail` is deliberately not exposed,
  since it carries raw ACME/DNS-provider response bodies. The field is optional in both directions,
  so old and new clients and servers interoperate. `RenewalManager` logs each entry, and self-signs
  only the domains that actually failed instead of the whole batch.

### Changed
- When `skip_failing=True` but *nothing* could be obtained — no new certificate and no reusable
  existing one — issuance still raises rather than returning an empty response, so a single-domain
  call keeps its previous loud behavior.
- Batched issuance (`batch_domains=True`, `issue_certificate_in_batches`) returns one certificate
  per wildcard instead of folding wildcards into a shared SAN list. Callers that mapped a
  requested host to an exact entry in `response.issued` should match through
  `certapi.domain_matching.domain_matches_cert_domain` instead; `RenewalManager` already does.
- `create_safe_domain_batches` emits wildcards as singleton batches. Depth-based grouping for
  concrete domains is unchanged.
- Custom `batch_generator` callables now receive only concrete domains; wildcards are split out
  before the generator runs.
- The declared minimum Python version is now 3.10, matching the type syntax used by the package.

## [1.1.0] - 2026-02-12
### Added
- Command-line interface (`certapi` / `cli`) exposing common workflows: `issue`, `renew`, `list`, and `revoke`.
- Config file support and environment variable overrides for local/CI usage.
- Enhanced logging, debug flags, and more informative CLI error messages.
### Changed
- Improved CLI-friendly output formats (plain text and JSON) for scripting and automation.
### Fixed
- Various integration and usability issues discovered during CLI testing.

## [1.0.5] - 2026-02-08
### Added
- Packaging and CI improvements: `pyproject.toml` / `requirements.txt` updates and release automation tweaks.
### Fixed
- Docker image tagging and Dockerfile fixes for reproducible builds.
- Miscellaneous minor bugfixes and documentation tweaks.

## [1.0.4] - 2026-02-02
### Added
- Postgres keystore robustness improvements and better sqlite fallback handling.
### Fixed
- Packaging metadata and dependency pinning issues causing install-time warnings.

## [1.0.3] - 2026-01-28
### Added
- Improved DNS provider integrations (Cloudflare/DigitalOcean) for TXT record cleanup.
### Fixed
- Race conditions during challenge creation and cleanup under heavy concurrency.
- Robustness fixes for order certificate retrieval and decoding.

## [1.0.2] - 2026-01-22
### Added
- Additional sanity checks when loading keys and certificates from keystores.
### Fixed
- Retry/backoff handling for transient HTTP and DNS provider errors.
- Test stability fixes for challenge cleanup routines.

## [1.0.1] - 2026-01-20
### Added
- Small improvements to logging and diagnostic output for ACME flows.
### Fixed
- Keystore path handling edge-cases that caused certificate lookups to fail.
- Minor bugfixes in ACME error parsing to avoid missing-detail exceptions.

## [1.0.0] - 2026-01-15
### Added
- Production Docker image (multi-arch, rootless, Gunicorn, port `8080`).
- Concurrency control with domain-level locking and renewal queuing.
- Configurable certificate renewal threshold (`CERT_RENEW_THRESHOLD_DAYS`).
- CI/CD workflow for automated GHCR publication.

### Fixed
- Standardized environment variables, error handling, and minor typos.


## [0.6.0] - 2026-01-12
### ToDo
- [] Certapi api and docker image
### Fixed
- Improved `AcmeHttpError` processing to handle missing response fields and prevent type errors during error message generation.
- Implemented configurable retry delays and error handling for connection reset errors.
- Fixed timezone deprecation warnings across the codebase.

## [0.5.1] - 2025-11-17
### Added
- Certificate expiry date check logic.
## Until 0.5.0-pre - 2025-08-24
### ToDo
- [] Certapi api and docker image
### Added
- Mechanism to prune all TXT records/challenges on startup in challenge stores.
- Logging of request bodies on errors for better debugging.
- Cleanup method to ChallengeSolver
- Missing __init__.py file in modules
- Refactor everything to proper Inheritance
- Workaround for fullchain cert
- DigitalOcean challenge store
- Allow custom store dir name, fix self-signed cert name
- Use PiPy api key for publishing
- Better error handling, add packaging
- Fix issues. make certificate issuing functional.
- Fix apis, make ready for testing
- Basic implementation [incomplete]

### Fixed
- SSL warning in Nginx related to fullchain certificates and keystore handling.
- Payload handling when re-trying failed requests.
- Log request body on errors
- Logging and Readme
- Remove extra file
- Logging verbosity in cloudflare
- Challenge solving logic
- Key, Challenge stores and tests
- Filesystem keystore
- Bugfix: Fix response usage in Order.get_certificate
- Bugfix: return str in Order.get_certificate not bytes
- Bugfix: Pass certificate string to keystore
- Bugfix: Handle ACME error with no detail
- Certificate save logic
- "detail" key missing error during acme error handling
- Bugfix fix selfsigned detection logic
- Bugfixes for dns challenge
- Crypto classes, add cloudflare challenge store
- Response type and error handling

### Changed
- Increased wait time for DNS propagation to 20 sec to improve reliability.
- Increase wait time for DNS propagation to 10 sec
- Refactor Challenge Solvers to use common base class
- Minor fixes, Improve challenge cleanup
- Proper error handling in DNS provider APIs
- Renames ChallengeStore to ChallengeSolver, other minor fixes
- Refactor CertIssuer, improve server
- Apply black formatter
- Update gitignore
- WIP enhance crypto classes
- Auto set release tag
- Change project name to certapi
