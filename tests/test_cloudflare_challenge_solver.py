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
