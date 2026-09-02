from certapi.challenge_solver.dns.cloudflare import cloudflare_challenge_solver
from certapi.challenge_solver.dns.cloudflare.cloudflare_challenge_solver import CloudflareChallengeSolver


class FakeCloudflare:
    def __init__(self, api_key=None):
        self.api_key = api_key


def test_cloudflare_solvers_from_environment(monkeypatch):
    monkeypatch.setattr(cloudflare_challenge_solver, "Cloudflare", FakeCloudflare)

    solvers = CloudflareChallengeSolver.from_environment(
        {
            "CLOUDFLARE_API_KEY": "primary",
            "CLOUDFLARE_API_KEY_2": " secondary ",
            "CLOUDFLARE_API_TOKEN": "ignored",
            "CLOUDFLARE_API_KEY_EMPTY": "",
            "OTHER": "ignored",
        }
    )

    assert [solver.cloudflare.api_key for solver in solvers] == ["primary", "secondary"]


class RecordingCloudflare(FakeCloudflare):
    """Records create/delete calls; create_record appends like the real TXT API."""

    def __init__(self, api_key=None):
        super().__init__(api_key)
        self.records = {}
        self.deleted = []
        self._next_id = 0

    def create_record(self, name, data, domain):
        self._next_id += 1
        record_id = f"rec-{self._next_id}"
        self.records[record_id] = (name, data, domain)
        return record_id

    def delete_record(self, record, domain):
        self.deleted.append(record)
        self.records.pop(record, None)


def test_shared_challenge_name_keeps_both_records_and_deletes_both(monkeypatch):
    """`example.com` and `*.example.com` share _acme-challenge.example.com with two values."""
    monkeypatch.setattr(cloudflare_challenge_solver, "Cloudflare", RecordingCloudflare)
    solver = CloudflareChallengeSolver("key")

    key = "_acme-challenge.example.com"
    solver.save_challenge(key, "value-apex", "example.com")
    solver.save_challenge(key, "value-wildcard", "example.com")

    assert len(solver) == 2
    assert len(solver.cloudflare.records) == 2

    solver.delete_challenge(key, "example.com")
    solver.delete_challenge(key, "example.com")

    assert sorted(solver.cloudflare.deleted) == ["rec-1", "rec-2"]
    assert solver.cloudflare.records == {}
    assert key not in solver.challenges_map
    assert len(solver) == 0


def test_delete_challenge_for_unknown_key_is_a_noop(monkeypatch):
    monkeypatch.setattr(cloudflare_challenge_solver, "Cloudflare", RecordingCloudflare)
    solver = CloudflareChallengeSolver("key")

    solver.delete_challenge("_acme-challenge.absent.com", "absent.com")

    assert solver.cloudflare.deleted == []
