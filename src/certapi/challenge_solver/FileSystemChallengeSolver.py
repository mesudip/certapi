from typing import Literal
from .ChallengeSolver import ChallengeSolver
import os
import secrets
import tempfile
import requests
import sys
import re


class FilesystemChallengeSolver(ChallengeSolver):
    """
    Filesystem implementation of the ChallengeSolver.
    This should never be used, but extended for your webserver e.g. nginx, apache etc.
    """

    def __init__(self, directory: str):
        self.directory = directory
        os.makedirs(self.directory, exist_ok=True)

    def supports_domain(self, domain: str) -> bool:
        return "*" not in domain

    def supports_domain_strict(self, domain: str) -> bool:
        return self.verify_domain(domain) if self.supports_domain(domain) else False

    def save_challenge(self, key: str, value: str, domain: str = None):
        file_path = os.path.join(self.directory, key)
        with open(file_path, "w") as file:
            file.write(value)

    def get_challenge(self, key: str, domain: str = None) -> str:
        file_path = os.path.join(self.directory, key)
        if not os.path.exists(file_path):
            return None
        with open(file_path, "r") as file:
            return file.read()

    def delete_challenge(self, key: str, domain: str = None):
        file_path = os.path.join(self.directory, key)
        if os.path.exists(file_path):
            os.remove(file_path)

    def supported_challenge_type(self) -> Literal["http-01"]:
        return "http-01"

    def cleanup_old_challenges(self):
        for filename in os.listdir(self.directory):
            file_path = os.path.join(self.directory, filename)
            if os.path.isfile(file_path):
                os.remove(file_path)

    def __iter__(self):
        return (f for f in os.listdir(self.directory) if os.path.isfile(os.path.join(self.directory, f)))

    @staticmethod
    def is_valid_hostname(hostname):
        if not hostname or len(hostname) > 255:
            return False
        if hostname[-1] == ".":
            hostname = hostname[:-1]

        allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(allowed.match(x) for x in hostname.split("."))

    def verify_domain(self, _domain: list | str):
        domains = [_domain] if isinstance(_domain, str) else list(dict.fromkeys(_domain))
        valid_domains = [domain for domain in domains if self.is_valid_hostname(domain)]
        success = []
        # Exclusive creation keeps simultaneous verification requests independent.
        with tempfile.NamedTemporaryFile(mode="wb", dir=self.directory, prefix="verify-", delete=False) as probe:
            token = os.path.basename(probe.name)
            expected = secrets.token_urlsafe(192).encode("ascii")
            probe.write(expected)
        try:
            # nginx workers may run as a different user from the process creating
            # the probe. This payload is intended to be publicly readable.
            os.chmod(probe.name, 0o644)
            for domain in valid_domains:
                url = f"http://{domain}/.well-known/acme-challenge/{token}"
                try:
                    response = requests.get(url, allow_redirects=False, timeout=3)
                    if response.status_code == 200 and response.content == expected:
                        success.append(domain)
                    else:
                        print(
                            f"[Error] [{domain}] HTTP challenge verification failed: "
                            f"status {response.status_code} or incorrect payload -> {url}",
                            file=sys.stderr,
                        )
                except requests.exceptions.RequestException as error:
                    print(f"[Error] [{domain}] HTTP challenge verification failed: {error}", file=sys.stderr)
        finally:
            os.remove(probe.name)
        return bool(success) if isinstance(_domain, str) else success
