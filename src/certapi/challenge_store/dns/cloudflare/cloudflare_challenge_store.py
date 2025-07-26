import os
from collections.abc import MutableMapping
from ...ChallengeStore import ChallengeStore
from .cloudflare_client import Cloudflare


class CloudflareChallengeStore(ChallengeStore):
    def __init__(self,api_key:str=None):
        self.cloudflare = Cloudflare(api_key)
        self.challenges_map = {} 

    def has_domain(self, domain: str) -> bool:
        """
        Checks if the Cloudflare account has access to the given domain (or its base domain)
        as a registered zone.
        """
        try:
            self.cloudflare.determine_registered_domain(domain)
            return True
        except Exception:
            return False

    def save_challenge(self, key: str, value: str, domain=None):
        # key example: _acme-challenge.sub.example.com
        # value example: ACME_CHALLENGE_TOKEN
        base_domain = self.cloudflare.determine_registered_domain(domain)

        record_id = self.cloudflare.create_record(name=key, data=value, domain=base_domain)
        self.challenges_map[key] = record_id
        print(f"CloudflareChallengeStore: Saved challenge for {key} with record ID {record_id}")

    def get_challenge(self, key: str, domain: str) -> str:
        base_domain = self.cloudflare.determine_registered_domain(domain)
        records = self.cloudflare.list_txt_records(base_domain, name_filter=key)
        for record in records:
            if record["name"] == key:
                return record["content"]
        return None  # Return None if not found, as per ChallengeStore's __getitem__ behavior

    def delete_challenge(self, key: str, domain: str):
        if key not in self.challenges_map:
            raise KeyError(f"Challenge {key} not found in store (no record_id stored).")

        record_id = self.challenges_map[key]
        base_domain = self.cloudflare.determine_registered_domain(domain)
        self.cloudflare.delete_record(record=record_id, domain=base_domain)
        del self.challenges_map[key]
        print(f"CloudflareChallengeStore: Deleted challenge for {key} with record ID {record_id}")

    def __iter__(self):
        # This is tricky as we can't easily iterate all challenges across all domains
        # If the user wants a full API-driven iteration, they need to clarify how to get all domains.
        return iter(self.challenges_map)

    def __len__(self):
        # Similar to __iter__, this will count challenges managed by this store instance.
        return len(self.challenges_map)
