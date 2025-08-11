from typing import Literal
from .ChallengeSolver import ChallengeSolver
import os


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

    def __len__(self):
        return len([f for f in os.listdir(self.directory) if os.path.isfile(os.path.join(self.directory, f))])
