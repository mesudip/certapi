from .ChallengeSolver import ChallengeSolver
from .InmemoryChallengeSolver import InMemoryChallengeSolver
import os
from .FileSystemChallengeSolver import FilesystemChallengeSolver
from .dns import CloudflareChallengeSolver, DigitalOceanChallengeSolver


def get_challenge_solver():
    """
    Factory function to determine the type of store based on environment variables.

    Environment Variables:
    - `challenge_solver_TYPE`: Can be "memory" or "filesystem".
    - `challenge_solver_DIR`: Directory for filesystem-based store. Defaults to "./challenges".
    """
    store_type = os.getenv("challenge_solver_TYPE", "filesystem").lower()
    directory = os.getenv("challenge_solver_DIR", "./challenges")

    if store_type == "memory":
        return InMemoryChallengeSolver()
    elif store_type == "filesystem":
        return FilesystemChallengeSolver(directory)
    else:
        raise ValueError(f"Unknown challenge_solver_TYPE: {store_type}")
