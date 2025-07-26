from .ChallengeStore import ChallengeStore


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
