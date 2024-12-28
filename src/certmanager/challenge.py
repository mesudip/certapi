import os
from collections.abc import MutableMapping


class ChallengeStore(MutableMapping):
    """
    Abstract base class for a challenge store.
    Provides dictionary-like behavior by inheriting from MutableMapping.
    """

    def __setitem__(self, key, value):
        self.save_challenge(key, value)

    def __getitem__(self, key):
        value = self.get_challenge(key)
        if value is None:
            raise KeyError(key)
        return value

    def __delitem__(self, key):
        if key not in self:
            raise KeyError(key)
        self.delete_challenge(key)

    def __contains__(self, key):
        return self.get_challenge(key) is not None

    def __iter__(self):
        raise NotImplementedError("Must implement `__iter__` method.")

    def __len__(self):
        raise NotImplementedError("Must implement `__len__` method.")

    def save_challenge(self, key: str, value: str):
        raise NotImplementedError("Must implement `save_challenge` method.")

    def get_challenge(self, key: str) -> str:
        raise NotImplementedError("Must implement `get_challenge` method.")

    def delete_challenge(self, key: str):
        raise NotImplementedError("Must implement `delete_challenge` method.")


class InMemoryChallengeStore(ChallengeStore):
    """
    In-memory implementation of the ChallengeStore.
    """

    def __init__(self):
        self.challenges = {}

    def save_challenge(self, key: str, value: str):
        self.challenges[key] = value

    def get_challenge(self, key: str) -> str:
        return self.challenges.get(key, None)

    def delete_challenge(self, key: str):
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

    def save_challenge(self, key: str, value: str):
        file_path = os.path.join(self.directory, key)
        with open(file_path, "w") as file:
            file.write(value)

    def get_challenge(self, key: str) -> str:
        file_path = os.path.join(self.directory, key)
        if not os.path.exists(file_path):
            return None
        with open(file_path, "r") as file:
            return file.read()

    def delete_challenge(self, key: str):
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
