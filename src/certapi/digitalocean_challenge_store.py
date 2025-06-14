import os
from collections.abc import MutableMapping
from certapi.challenge import ChallengeStore
from certapi.digitalocean_client import DigitalOcean


class DigitalOceanChallengeStore(ChallengeStore):
    def __init__(self):
        self.digitalocean = DigitalOcean()
        self.challenges_map = {}  # Stores key: record_id (needed for deletion)

    def has_domain(self, domain: str) -> bool:
        """
        Checks if the DigitalOcean account has access to the given domain (or its base domain)
        as a registered zone.
        """
        try:
            self.digitalocean.determine_domain(domain)
            return True
        except Exception:
            return False

    def save_challenge(self, key: str, value: str, domain=None):
        # key example: _acme-challenge.sub.example.com
        # value example: ACME_CHALLENGE_TOKEN
        base_domain = self.digitalocean.determine_domain(domain)

        record_id = self.digitalocean.create_record(name=key, data=value, domain=base_domain)
        self.challenges_map[key] = record_id
        print(f"DigitalOceanChallengeStore: Saved challenge for {key} with record ID {record_id}")

    def get_challenge(self, key: str, domain: str) -> str:
        base_domain = self.digitalocean.determine_domain(domain)
        records = self.digitalocean.list_records(base_domain, name_filter=key)
        for record in records:
            if record["name"] == key:
                return record["data"] # DigitalOcean API returns 'data' for TXT record content
        return None  # Return None if not found, as per ChallengeStore's __getitem__ behavior

    def delete_challenge(self, key: str, domain: str):
        if key not in self.challenges_map:
            raise KeyError(f"Challenge {key} not found in store (no record_id stored).")

        record_id = self.challenges_map[key]
        base_domain = self.digitalocean.determine_domain(domain)
        self.digitalocean.delete_record(record=record_id, domain=base_domain)
        del self.challenges_map[key]
        print(f"DigitalOceanChallengeStore: Deleted challenge for {key} with record ID {record_id}")

    def __iter__(self):
        # This is tricky as we can't easily iterate all challenges across all domains
        # If the user wants a full API-driven iteration, they need to clarify how to get all domains.
        return iter(self.challenges_map)

    def __len__(self):
        # Similar to __iter__, this will count challenges managed by this store instance.
        return len(self.challenges_map)
