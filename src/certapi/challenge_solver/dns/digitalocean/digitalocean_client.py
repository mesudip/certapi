import json
from os import getenv
from certapi.errors import CertApiException, HttpError, NetworkError, DomainNotOwnedException
from certapi.http import client as http_client
from urllib.request import Request


class DigitalOcean(object):
    def __init__(self, api_key: str = None):
        self.token = api_key
        self.api = "https://api.digitalocean.com/v2/domains"
        if not self.token:
            self.token = getenv("DIGITALOCEAN_API_KEY")
            if not self.token:
                raise CertApiException("DIGITALOCEAN_API_KEY not found in environment", step="DigitalOcean.__init__")

    def _get_domains(self):
        """Fetch DigitalOcean domains"""
        request_headers = {"Content-Type": "application/json", "Authorization": "Bearer {0}".format(self.token)}
        response = http_client.get(self.api, headers=request_headers, step="DigitalOcean Get Domains")
        return response.json()["domains"]

    def determine_domain(self, domain):
        """Determine registered domain in API"""
        domains = self._get_domains()
        for d in domains:
            if d["name"] in domain:
                return d["name"]
        raise DomainNotOwnedException(
            "No DigitalOcean domain found for: {0}".format(domain),
            detail={"domain": domain},
            step="DigitalOcean Determine Domain"
        )

    def create_record(self, name, data, domain):
        """
        Create DNS record
        Params:
            name, string, record name
            data, string, record data
            domain, string, dns domain
        Return:
            record_id, int, created record id
        """
        registered_domain = self.determine_domain(domain)
        api = self.api + "/" + registered_domain + "/records"
        request_headers = {"Content-Type": "application/json", "Authorization": "Bearer {0}".format(self.token)}
        request_data = {"type": "TXT", "ttl": 300, "name": name, "data": data}
        response = http_client.post(api, headers=request_headers, json=request_data, step="DigitalOcean Create Record")
        if response.status_code != 201:
            raise HttpError(
                response=response,
                message="DigitalOcean API error",
                detail=response.json(),
                step="DigitalOcean Create Record"
            )
        return response.json()["domain_record"]["id"]

    def delete_record(self, record, domain):
        """
        Delete DNS record
        Params:
            record, int, record id number
            domain, string, dns domain
        """
        registered_domain = self.determine_domain(domain)
        api = self.api + "/" + registered_domain + "/records/" + str(record)
        request_headers = {"Content-Type": "application/json", "Authorization": "Bearer {0}".format(self.token)}
        response = http_client.delete(api, headers=request_headers, step="DigitalOcean Delete Record")
        if response.status_code != 204:
            raise HttpError(
                response=response,
                message="DigitalOcean API error",
                detail=response.json(),
                step="DigitalOcean Delete Record"
            )

    def list_records(self, domain, name_filter=None):
        """
        List DNS records for a domain, optionally filtered by name.
        Params:
            domain, string, dns domain
            name_filter, string, optional filter for record name
        Return:
            records, list of dicts, matching DNS records
        """
        registered_domain = self.determine_domain(domain)
        api = self.api + "/" + registered_domain + "/records"
        request_headers = {"Content-Type": "application/json", "Authorization": "Bearer {0}".format(self.token)}
        response = http_client.get(api, headers=request_headers, step="DigitalOcean List Records")

        all_records = response.json()["domain_records"]

        if name_filter:
            filtered_records = [r for r in all_records if r["name"] == name_filter and r["type"] == "TXT"]
        else:
            filtered_records = [r for r in all_records if r["type"] == "TXT"]

        return filtered_records
