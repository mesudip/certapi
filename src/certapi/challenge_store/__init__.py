from .ChallengeStore import ChallengeStore
from .InmemoryChallengeStore import InMemoryChallengeStore
import os
from .FileSystemChallengeStore import FileSystemChallengeStore
from .dns import CloudflareChallengeStore,DigitalOceanChallengeStore

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


