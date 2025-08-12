import os
import time
from collections.abc import MutableMapping
from typing import Literal, Callable, Any
from ...ChallengeSolver import ChallengeSolver
from .digitalocean_client import DigitalOcean
from certapi.errors import CertApiException, NetworkError


class DigitalOceanChallengeSolver(ChallengeSolver):
    def __init__(self, api_key: str = None):
        self.digitalocean = DigitalOcean(api_key)
        self.challenges_map = {}  # Stores key: record_id (needed for deletion)

    def supported_challenge_type(self) -> Literal["dns-01"]:
        return "dns-01"

    def supports_domain(self, domain: str) -> bool:
        """
        Checks if the DigitalOcean account has access to the given domain (or its base domain)
        as a registered zone.
        """
        try:
            self.digitalocean.determine_registered_domain(domain)
            return True
        except CertApiException as e:
            # Log the exception or handle it as needed, but return False as it doesn't support the domain
            print(f"DigitalOceanChallengeSolver.supports_domain: {e.message} - {e.detail}")
            return False

    def save_challenge(self, key: str, value: str, domain=None):
        # key example: _acme-challenge.sub.example.com
        # value example: ACME_CHALLENGE_TOKEN
        base_domain = self.digitalocean.determine_registered_domain(domain)

        record_id = self.digitalocean.create_record(name=key, data=value, domain=base_domain)
        self.challenges_map[key] = record_id
        print(f"DigitalOceanChallengeSolver: Saved challenge for {key} with record ID {record_id}")

    def get_challenge(self, key: str, domain: str) -> str:
        base_domain = self.digitalocean.determine_registered_domain(domain)
        records = self.digitalocean.list_txt_records(base_domain, name_filter=key)
        for record in records:
            if record["name"] == key:
                return record["data"]  # DigitalOcean API returns 'data' for TXT record content
        return None  # Return None if not found, as per ChallengeSolver's __getitem__ behavior

    def delete_challenge(self, key: str, domain: str):
        if key not in self.challenges_map:
            raise KeyError(f"Challenge {key} not found in store (no record_id stored).")

        record_id = self.challenges_map[key]
        base_domain = self.digitalocean.determine_registered_domain(domain)
        self.digitalocean.delete_record(record=record_id, domain=base_domain)
        del self.challenges_map[key]
        print(f"DigitalOceanChallengeSolver: Deleted challenge for {key} with record ID {record_id}")

    def cleanup_old_challenges(self):
        domains = self.digitalocean._get_domains()
        for domain_obj in domains:
            domain_name = domain_obj["name"]
            try:
                records = self.digitalocean.list_txt_records(domain_name)
                for record in records:
                    if record["type"] == "TXT" and record["name"].startswith("_acme-challenge"):
                        print(
                            f"DigitalOceanChallengeSolver: Deleting old challenge record {record['name']} in domain {domain_name}"
                        )
                        try:
                            self.digitalocean.delete_record(record["id"], domain_name)
                        except CertApiException as e:
                            print(
                                f"DigitalOceanChallengeSolver: Warning - Failed to delete record {record['name']} in domain {domain_name}: {e.message} - {e.detail}"
                            )
                        except Exception as e:
                            print(
                                f"DigitalOceanChallengeSolver: Warning - An unexpected error occurred while deleting record {record['name']} in domain {domain_name}: {e}"
                            )
            except CertApiException as e:
                print(
                    f"DigitalOceanChallengeSolver: Error listing challenges in domain {domain_name}: {e.message} - {e.detail}"
                )
            except Exception as e:
                print(
                    f"DigitalOceanChallengeSolver: An unexpected error occurred while listing challenges in domain {domain_name}: {e}"
                )

    def __iter__(self):
        # This is tricky as we can't easily iterate all challenges across all domains
        # If the user wants a full API-driven iteration, they need to clarify how to get all domains.
        return iter(self.challenges_map)

    def __len__(self):
        # Similar to __iter__, this will count challenges managed by this store instance.
        return len(self.challenges_map)
