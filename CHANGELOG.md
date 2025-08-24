# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
