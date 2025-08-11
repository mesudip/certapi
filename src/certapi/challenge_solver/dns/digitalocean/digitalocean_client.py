import json
from os import getenv
from urllib.request import urlopen, Request
from certapi.errors import CertApiException


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
        response = urlopen(Request(self.api, headers=request_headers))
        if response.getcode() != 200:
            raise CertApiException(
                "DigitalOcean API error",
                detail=json.loads(response.read().decode("utf8")),
                step="DigitalOcean._get_domains"
            )
        return json.loads(response.read().decode("utf8"))["domains"]

    def determine_domain(self, domain):
        """Determine registered domain in API"""
        domains = self._get_domains()
        for d in domains:
            if d["name"] in domain:
                return d["name"]
        raise CertApiException(
            "No DigitalOcean domain found for: {0}".format(domain),
            detail={"domain": domain},
            step="DigitalOcean.determine_domain"
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
        response = urlopen(Request(api, data=json.dumps(request_data).encode("utf8"), headers=request_headers))
        if response.getcode() != 201:
            raise CertApiException(
                "DigitalOcean API error",
                detail=json.loads(response.read().decode("utf8")),
                step="DigitalOcean.create_record"
            )
        return json.loads(response.read().decode("utf8"))["domain_record"]["id"]

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
        request = Request(api, data=json.dumps({}).encode("utf8"), headers=request_headers)
        request.get_method = lambda: "DELETE"
        response = urlopen(request)
        if response.getcode() != 204:
            raise CertApiException(
                "DigitalOcean API error",
                detail=json.loads(response.read().decode("utf8")),
                step="DigitalOcean.delete_record"
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
        response = urlopen(Request(api, headers=request_headers))
        if response.getcode() != 200:
            raise CertApiException(
                "DigitalOcean API error",
                detail=json.loads(response.read().decode("utf8")),
                step="DigitalOcean.list_records"
            )

        all_records = json.loads(response.read().decode("utf8"))["domain_records"]

        if name_filter:
            filtered_records = [r for r in all_records if r["name"] == name_filter and r["type"] == "TXT"]
        else:
            filtered_records = [r for r in all_records if r["type"] == "TXT"]

        return filtered_records
