import json
import time
from os import getenv
from certapi.errors import CertApiException, HttpError, DomainNotOwnedException
from certapi.http.HttpClientBase import HttpClientBase
from urllib.parse import urlencode
from urllib.request import Request


class Cloudflare(HttpClientBase):
    name = "cloudflare"

    def __init__(self, api_key: str = None):
        if not api_key:
            api_key = getenv("CLOUDFLARE_API_KEY")
            if not api_key:
                raise CertApiException("CLOUDFLARE_API_KEY not found in environment", step="Cloudflare.__init__")

        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
        super().__init__("https://api.cloudflare.com/client/v4", headers, auto_retry=True)
        self._zones_cache = None
        self._zones_cache_time = 0  # Unix timestamp of last cache update

    def _get_zones(self):
        """Fetch and cache Cloudflare zones"""
        # Cache for 1 day (86400 seconds)
        if self._zones_cache and (time.time() - self._zones_cache_time) < 86400:
            return self._zones_cache

        api_url = f"{self.api_base_url}/zones?per_page=50"
        response = self._get(api_url, step="Cloudflare Get Zones")

        zones = response.json()["result"]
        self._zones_cache = zones
        self._zones_cache_time = time.time()
        return zones

    def _get_zone_id_(self, domain):
        """Determine Cloudflare Zone ID for a given domain"""
        zones = self._get_zones()
        for zone in zones:
            if zone["name"] == domain:
                return zone["id"]

    def _get_zone_id(self, domain):
        """Determine Cloudflare Zone ID for a given domain"""
        zone_id = self._get_zone_id_(domain)
        if zone_id is None:
            raise DomainNotOwnedException(
                "No Cloudflare zone found for domain", detail={"domain": domain}, step="Cloudflare Get Zone ID"
            )

    def _determine_zone_id(self, domain: str) -> str:
        """
        Determine the registered domain in Cloudflare and return its Zone ID.
        This method encapsulates the logic of finding the correct zone for a given domain.
        """
        registered_domain = self.determine_registered_domain(domain)
        zone_id = self._get_zone_id_(registered_domain)
        return zone_id

    def determine_registered_domain(self, domain: str) -> str:
        """
        Determine the registered domain in Cloudflare for a given (sub)domain.
        This method iterates through parts of the domain to find a matching Cloudflare zone.
        """
        parts = domain.split(".")
        err = None
        for i in range(len(parts)):
            potential_domain = ".".join(parts[i:])
            if self._get_zone_id_(potential_domain) is not None:
                return potential_domain

        raise DomainNotOwnedException(
            "No Cloudflare zone found for " + domain, detail={"domain": domain}, step="Cloudflare Get Zone ID"
        )

    def list_txt_records(self, domain: str, name_filter: str = None) -> list:
        """
        Lists TXT records for a given domain, optionally filtered by name.
        Returns a list of dictionaries, each representing a TXT record.
        """
        zone_id = self._determine_zone_id(domain)
        params = {"type": "TXT"}
        if name_filter:
            params["name"] = name_filter

        api_url = f"{self.api_base_url}/zones/{zone_id}/dns_records?{urlencode(params)}"

        response = self._get(api_url, step="Cloudflare List TXT Records")

        result = response.json()
        if not result.get("success"):
            raise CertApiException(
                "Unknown error listing TXT records",
                detail=result.get("errors", "Unknown error listing TXT records"),
                step="Cloudflare List TXT Records",
            )

        return result["result"]

    def create_record(self, name, data, domain):
        """
        Create DNS record
        Params:
            name, string, record name (e.g., _acme-challenge.example.com)
            data, string, record data (e.g., ACME challenge token)
            domain, string, dns domain (e.g., example.com) - This will be used to determine the registered zone.
        Return:
            record_id, string, created record id
        """
        zone_id = self._determine_zone_id(domain)
        api_url = "{0}/zones/{1}/dns_records".format(self.api_base_url, zone_id)
        request_data = {
            "type": "TXT",
            "name": name,
            "content": data,
            "ttl": 120,  # Cloudflare minimum TTL for TXT is 120 seconds
            "proxied": False,
        }
        response = self._post(api_url, json_data=request_data, step="Cloudflare Create Record")
        result = response.json()
        return result["result"]["id"]

    def delete_record(self, record, domain):
        """
        Delete DNS record
        Params:
            record, string, record id number
            domain, string, dns domain - This will be used to determine the registered zone.
        """
        zone_id = self._determine_zone_id(domain)
        api_url = "{0}/zones/{1}/dns_records/{2}".format(self.api_base_url, zone_id, record)
        self._delete(api_url, step="Cloudflare Delete Record")
