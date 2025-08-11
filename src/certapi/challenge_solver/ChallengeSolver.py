from abc import ABC, abstractmethod
import os
from collections.abc import MutableMapping
from typing import Literal


class ChallengeSolver(ABC):
    """
    Abstract base class for a challenge store.
    """

    @abstractmethod
    def supports_domain(self, domain: str) -> bool:
        pass

    @abstractmethod
    def save_challenge(self, key: str, value: str, domain: str = None):
        pass

    @abstractmethod
    def get_challenge(self, key: str, domain: str = None) -> str:
        pass

    @abstractmethod
    def delete_challenge(self, key: str, domain: str = None):
        pass

    @abstractmethod
    def supported_challenge_type(self) -> Literal["http-01", "dns-01", "tls-alpn-01"]:
        pass

    @abstractmethod
    def cleanup_old_challenges(self):
        pass

    def __iter__(self):
        raise NotImplementedError("Must implement `__iter__` method.")

    def __len__(self):
        raise NotImplementedError("Must implement `__len__` method.")
