import os
import time
from collections.abc import MutableMapping
from typing import Literal, Callable, Any
from concurrent.futures import ThreadPoolExecutor
from ...ChallengeSolver import ChallengeSolver
from .cloudflare_client import Cloudflare
from certapi.errors import CertApiException, DomainNotOwnedException, NetworkError

MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 5


class CloudflareChallengeSolver(ChallengeSolver):
    def __init__(self, api_key: str = None):
        self.cloudflare = Cloudflare(api_key)
        self.challenges_map = {}

    def _retry_api_call(self, func: Callable, *args, **kwargs) -> Any:
        retries = 0
        while retries <= MAX_RETRIES:
            try:
                return func(*args, **kwargs)
            except CertApiException as e:
                if e.can_retry and retries < MAX_RETRIES:
                    print(f"CloudflareChallengeSolver: Retrying due to retryable error: {e.message}. Attempt {retries + 1}/{MAX_RETRIES}")
                    time.sleep(RETRY_DELAY_SECONDS)
                    retries += 1
                else:
                    raise
            except Exception as e:
                # Catch any other unexpected exceptions and re-raise
                raise CertApiException(f"An unexpected error occurred: {e}", step=f"{func.__name__}") from e
        # This part should ideally not be reached if MAX_RETRIES is handled by the loop
        raise CertApiException("Max retries exceeded for API call.", step=f"{func.__name__}")


    def supported_challenge_type(self) -> Literal["dns-01"]:
        return "dns-01"

    def supports_domain(self, domain: str) -> bool:
        """
        Checks if the Cloudflare account has access to the given domain (or its base domain)
        as a registered zone.
        """
        try:
            self._retry_api_call(self.cloudflare.determine_registered_domain, domain)
            return True
        except DomainNotOwnedException as e:
            return False

    def save_challenge(self, key: str, value: str, domain=None):
        # key example: _acme-challenge.sub.example.com
        # value example: ACME_CHALLENGE_TOKEN
        base_domain = self._retry_api_call(self.cloudflare.determine_registered_domain, domain)

        record_id = self._retry_api_call(self.cloudflare.create_record, name=key, data=value, domain=base_domain)
        self.challenges_map[key] = record_id
        print(f"CloudflareChallengeSolver[{domain}]: Added Record {key}")

    def get_challenge(self, key: str, domain: str) -> str:
        base_domain = self._retry_api_call(self.cloudflare.determine_registered_domain, domain)
        records = self._retry_api_call(self.cloudflare.list_txt_records, base_domain, name_filter=key)
        for record in records:
            if record["name"] == key:
                return record["content"]
        return None

    def delete_challenge(self, key: str, domain: str):
        if key not in self.challenges_map:
            print(f"CloudflareChallengeSolver.delete: Not found Skipping  key={key}  domain={domain}")
            return

        record_id = self.challenges_map[key]
        base_domain = self._retry_api_call(self.cloudflare.determine_registered_domain, domain)
        self._retry_api_call(self.cloudflare.delete_record, record=record_id, domain=base_domain)
        del self.challenges_map[key]
        print(f"CloudflareChallengeSolver: Deleted challenge for {key} with record ID {record_id}")

    def _cleanup_zone_challenges(self, zone):
        zone_name = zone["name"]
        try:
            # List all TXT records in the zone
            records = self._retry_api_call(self.cloudflare.list_txt_records, zone_name)
            for record in records:
                if record["type"] == "TXT" and record["name"].startswith("_acme-challenge"):
                    print(f"CloudflareChallengeSolver: Deleting old challenge record {record['name']} in zone {zone_name}")
                    try:
                        self._retry_api_call(self.cloudflare.delete_record, record["id"], zone_name)
                    except CertApiException as e:
                        print(f"CloudflareChallengeSolver: Warning - Failed to delete record {record['name']} in zone {zone_name}: {e.message} - {e.detail}")
                    except Exception as e:
                        print(f"CloudflareChallengeSolver: Warning - An unexpected error occurred while deleting record {record['name']} in zone {zone_name}: {e}")
        except CertApiException as e:
            print(f"CloudflareChallengeSolver: Error listing challenges in zone {zone_name}: {e.message} - {e.detail}")
        except Exception as e:
            print(f"CloudflareChallengeSolver: An unexpected error occurred while listing challenges in zone {zone_name}: {e}")

    def cleanup_old_challenges(self):
        zones = self._retry_api_call(self.cloudflare._get_zones)
        with ThreadPoolExecutor(max_workers=len(zones)) as executor:
            executor.map(self._cleanup_zone_challenges, zones)

    def __iter__(self):
        # This is tricky as we can't easily iterate all challenges across all domains
        # If the user wants a full API-driven iteration, they need to clarify how to get all domains.
        return iter(self.challenges_map)

    def __len__(self):
        # Similar to __iter__, this will count challenges managed by this store instance.
        return len(self.challenges_map)
