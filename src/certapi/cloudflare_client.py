import json
import time
from os import getenv
from urllib.request import urlopen, Request


class Cloudflare(object):
    name = "cloudflare"

    def __init__(self):
        self.token = getenv("CLOUDFLARE_API_TOKEN")
        self.account_id = getenv("CLOUDFLARE_ACCOUNT_ID")
        self.api = "https://api.cloudflare.com/client/v4"
        if not self.token:
            raise Exception("CLOUDFLARE_API_TOKEN not found in environment")

        self._zones_cache = None
        self._zones_cache_time = 0  # Unix timestamp of last cache update

    def _cloudflare_headers(self):
        return {"Content-Type": "application/json", "Authorization": "Bearer " + self.token}

    def _get_zones(self):
        """Fetch and cache Cloudflare zones"""
        # Cache for 1 day (86400 seconds)
        if self._zones_cache and (time.time() - self._zones_cache_time) < 86400:
            return self._zones_cache

        request_headers = self._cloudflare_headers()
        api_url = "{0}/zones?per_page=50".format(self.api)
        response = urlopen(Request(api_url, headers=request_headers))
        if response.getcode() != 200:
            raise Exception(json.loads(response.read().decode("utf8")))

        zones = json.loads(response.read().decode("utf8"))["result"]
        self._zones_cache = zones
        self._zones_cache_time = time.time()
        return zones

    def _get_zone_id(self, domain):
        """Determine Cloudflare Zone ID for a given domain"""
        zones = self._get_zones()
        for zone in zones:
            if zone["name"] == domain:
                return zone["id"]
        raise Exception("No Cloudflare zone found for domain: {0}".format(domain))

    def determine_registered_domain(self, domain: str) -> str:
        """
        Determine the registered domain in Cloudflare for a given (sub)domain.
        This method iterates through parts of the domain to find a matching Cloudflare zone.
        """
        parts = domain.split(".")
        err = None
        for i in range(len(parts)):
            potential_domain = ".".join(parts[i:])
            try:
                self._get_zone_id(potential_domain)
                return potential_domain
            except Exception as e:
                err = e
                continue
        if err:
            raise err
        else:
            raise Exception("Could not determine Cloudflare registered domain for: {0}".format(domain))

    def list_txt_records(self, domain: str, name_filter: str = None) -> list:
        """
        Lists TXT records for a given domain, optionally filtered by name.
        Returns a list of dictionaries, each representing a TXT record.
        """
        registered_domain = self.determine_registered_domain(domain)
        zone_id = self._get_zone_id(registered_domain)
        api_url = f"{self.api}/zones/{zone_id}/dns_records?type=TXT"
        if name_filter:
            api_url += f"&name={name_filter}"

        request_headers = self._cloudflare_headers()
        response = urlopen(Request(api_url, headers=request_headers))

        if response.getcode() != 200:
            raise Exception(json.loads(response.read().decode("utf8")))

        result = json.loads(response.read().decode("utf8"))
        if not result.get("success"):
            raise Exception(result.get("errors", "Unknown error listing TXT records"))

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
        registered_domain = self.determine_registered_domain(domain)
        zone_id = self._get_zone_id(registered_domain)
        api_url = "{0}/zones/{1}/dns_records".format(self.api, zone_id)
        request_headers = self._cloudflare_headers()
        request_data = {
            "type": "TXT",
            "name": name,
            "content": data,
            "ttl": 120,  # Cloudflare minimum TTL for TXT is 120 seconds
            "proxied": False,
        }
        response = urlopen(Request(api_url, data=json.dumps(request_data).encode("utf8"), headers=request_headers))

        if response.getcode() != 200:
            raise Exception(json.loads(response.read().decode("utf8")))
        result = response.read().decode("utf8")
        print("Cloudflare create record", name, result)
        return json.loads(result)["result"]["id"]

    def delete_record(self, record, domain):
        """
        Delete DNS record
        Params:
            record, string, record id number
            domain, string, dns domain - This will be used to determine the registered zone.
        """
        registered_domain = self.determine_registered_domain(domain)
        zone_id = self._get_zone_id(registered_domain)
        api_url = "{0}/zones/{1}/dns_records/{2}".format(self.api, zone_id, record)
        request_headers = self._cloudflare_headers()
        request = Request(api_url, headers=request_headers)
        request.get_method = lambda: "DELETE"
        response = urlopen(request)
        result = response.read().decode("utf8")
        print(f"Delete dns record [{response.getcode()}]", result)
        if response.getcode() != 200:
            raise Exception(json.loads(response.read().decode("utf8")))
