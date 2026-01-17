from typing import Literal
from .ChallengeSolver import ChallengeSolver
import os
import random
import string
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
        domain = [_domain] if type(_domain) is str else _domain

        # Simple hostname validation
        domain = [x for x in domain if self.is_valid_hostname(x)]
        success = []
        while True:
            r1 = "".join([random.choice(string.ascii_letters + string.digits) for _ in range(32)])
            file = os.path.join(self.directory, r1)
            if os.path.exists(file):
                continue
            r2 = "".join([random.choice(string.ascii_letters + string.digits) for _ in range(256)])
            with open(file, mode="wt") as file_descriptor:
                file_descriptor.write(r2)
            for d in domain:
                try:
                    url = "http://%s/.well-known/acme-challenge/%s" % (d, r1)
                    response = requests.get(url, allow_redirects=False, timeout=3)
                    if response.status_code == 200:
                        if response.content.decode("utf-8") == r2:
                            success.append(d)
                            continue
                    print(
                        "[Error] ["
                        + d
                        + "] Not owned by this machine:"
                        + "Status Code["
                        + str(response.status_code)
                        + "] -> "
                        + url,
                        file=sys.stderr,
                    )
                    continue
                except requests.exceptions.RequestException as e:
                    error = str(e)
                    if error.find("Name does not resolve") > -1:
                        print("[Error] [" + d + "] Domain Name could not be resolved", file=sys.stderr)
                    elif error.find("Connection refused") > -1:
                        print(
                            "[Error] [" + d + "] Connection Refused! The port is filtered or not open.", file=sys.stderr
                        )
                    else:
                        print("[ERROR] [" + d + "] Not owned by this machine : " + str(e))
                    continue
            os.remove(file)
            break
        if type(_domain) is str:
            return len(success) > 0
        else:
            return success
