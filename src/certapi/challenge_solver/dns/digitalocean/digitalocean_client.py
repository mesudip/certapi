import time
from os import getenv
from certapi.errors import CertApiException, DomainNotOwnedException
from certapi.http.HttpClientBase import HttpClientBase


class DigitalOcean(HttpClientBase):
    name = "digitalocean"

    def __init__(self, api_key: str = None):
        if not api_key:
            api_key = getenv("DIGITALOCEAN_API_KEY")
            if not api_key:
                raise CertApiException("DIGITALOCEAN_API_KEY not found in environment", step="DigitalOcean.__init__")

        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
        super().__init__("https://api.digitalocean.com/v2/domains", headers, auto_retry=True)
        self._domains_cache = None
        self._domains_cache_time = 0  # Unix timestamp of last cache update

    def _get_domains(self):
        """Fetch and cache DigitalOcean domains"""
        # Cache for 1 day (86400 seconds)
        if self._domains_cache and (time.time() - self._domains_cache_time) < 86400:
            return self._domains_cache

        response = self._get(self.api_base_url, step="DigitalOcean Get Domains")
        domains = response.json()["domains"]
        self._domains_cache = domains
        self._domains_cache_time = time.time()
        return domains

    def determine_registered_domain(self, domain: str) -> str:
        """
        Determine the registered domain in DigitalOcean for a given (sub)domain.
        This method iterates through parts of the domain to find a matching DigitalOcean domain.
        """
        domains = self._get_domains()
        domain_parts = domain.split(".")
        for i in range(len(domain_parts)):
            sub_domain = ".".join(domain_parts[i:])
            for d in domains:
                if d["name"] == sub_domain:
                    return sub_domain
        raise DomainNotOwnedException(
            "No DigitalOcean domain found for " + domain,
            detail={"domain": domain},
            step="DigitalOcean Determine Domain",
        )

    def list_txt_records(self, domain: str, name_filter: str = None) -> list:
        """
        Lists TXT records for a given domain, optionally filtered by name.
        Returns a list of dictionaries, each representing a TXT record.
        """
        registered_domain = self.determine_registered_domain(domain)
        api_url = f"{self.api_base_url}/{registered_domain}/records"

        response = self._get(api_url, step="DigitalOcean List TXT Records")

        all_records = response.json()["domain_records"]

        if name_filter:
            filtered_records = [r for r in all_records if r["name"] == name_filter and r["type"] == "TXT"]
        else:
            filtered_records = [r for r in all_records if r["type"] == "TXT"]

        return filtered_records

    def create_record(self, name, data, domain):
        """
        Create DNS record
        """
        registered_domain = self.determine_registered_domain(domain)
        api_url = f"{self.api_base_url}/{registered_domain}/records"
        request_data = {
            "type": "TXT",
            "name": name,
            "data": data,
            "ttl": 300,
        }
        response = self._post(api_url, json_data=request_data, step="DigitalOcean Create Record")
        return response.json()["domain_record"]["id"]

    def delete_record(self, record, domain):
        """
        Delete DNS record
        """
        registered_domain = self.determine_registered_domain(domain)
        api_url = f"{self.api_base_url}/{registered_domain}/records/{record}"
        self._delete(api_url, step="DigitalOcean Delete Record")
