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


class InMemoryChallengeStore(ChallengeStore):
    """
    In-memory implementation of the ChallengeStore.
    """

    def __init__(self):
        self.challenges = {}

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


class FileSystemChallengeStore(ChallengeStore):
    """
    Filesystem implementation of the ChallengeStore.
    """

    def __init__(self, directory: str):
        self.directory = directory
        os.makedirs(self.directory, exist_ok=True)

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

    def __iter__(self):
        return (f for f in os.listdir(self.directory) if os.path.isfile(os.path.join(self.directory, f)))

    def __len__(self):
        return len([f for f in os.listdir(self.directory) if os.path.isfile(os.path.join(self.directory, f))])


def get_challenge_store():
    """
    Factory function to determine the type of store based on environment variables.

    Environment Variables:
    - `CHALLENGE_STORE_TYPE`: Can be "memory" or "filesystem".
    - `CHALLENGE_STORE_DIR`: Directory for filesystem-based store. Defaults to "./challenges".
    """
    store_type = os.getenv("CHALLENGE_STORE_TYPE", "filesystem").lower()
    directory = os.getenv("CHALLENGE_STORE_DIR", "./challenges")

    if store_type == "memory":
        return InMemoryChallengeStore()
    elif store_type == "filesystem":
        return FileSystemChallengeStore(directory)
    else:
        raise ValueError(f"Unknown CHALLENGE_STORE_TYPE: {store_type}")


challenge_store: ChallengeStore = get_challenge_store()
