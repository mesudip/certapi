from typing import Literal
from .ChallengeSolver import ChallengeSolver


class InMemoryChallengeSolver(ChallengeSolver):
    """
    In-memory implementation of the ChallengeSolver.
    """

    def __init__(self):
        self.challenges = {}

    def supported_challenge_type(self) -> Literal["http-01"]:
        return "http-01"

    def save_challenge(self, key: str, value: str, domain: str = None):
        self.challenges[key] = value

    def get_challenge(self, key: str, domain: str = None) -> str:
        return self.challenges.get(key, "")

    def delete_challenge(self, key: str, domain: str = None):
        if key in self.challenges:
            del self.challenges[key]

    def __iter__(self):
        return iter(self.challenges)

    def __len__(self):
        return len(self.challenges)
