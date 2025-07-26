import os
from collections.abc import MutableMapping


class ChallengeStore:
    """
    Abstract base class for a challenge store.
    """
    def save_challenge(self, key: str, value: str, domain: str = None):
        raise NotImplementedError("Must implement `save_challenge` method.")

    def get_challenge(self, key: str, domain: str = None) -> str:
        raise NotImplementedError("Must implement `get_challenge` method.")

    def delete_challenge(self, key: str, domain: str = None):
        raise NotImplementedError("Must implement `delete_challenge` method.")

    def __iter__(self):
        raise NotImplementedError("Must implement `__iter__` method.")

    def __len__(self):
        raise NotImplementedError("Must implement `__len__` method.")