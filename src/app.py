import os
import sys
import traceback
from typing import List

from flask import Flask, jsonify, request
from flask_restx import Api, Namespace
from certapi.crypto.crypto_classes import Key
from certapi.server.api import create_api_resources, RenewalQueueFullError
from certapi.server.key_api import create_key_resources
from certapi.server.cert_api import create_cert_resources
from certapi.acme.Acme import AcmeError, AcmeHttpError, AcmeNetworkError
from certapi.errors import CertApiException
from certapi.utils import print_filtered_traceback
from certapi.challenge_solver import ChallengeSolver, FilesystemChallengeSolver
from certapi.challenge_solver.dns.cloudflare.cloudflare_challenge_solver import CloudflareChallengeSolver
from certapi.keystore import KeyStore, FileSystemKeyStore
from certapi.issuers import AcmeCertIssuer, SelfCertIssuer
from certapi.manager.acme_cert_manager import AcmeCertManager


app = Flask(__name__)
app.config["challenges"] = {}
app.config["RESTX_MASK_SWAGGER"] = False

# Initialize Flask-RESTX API
api = Api(
    app,
    version="1.0",
    title="CertManager API",
    description="A comprehensive API for managing SSL/TLS certificates.",
    doc="/docs",
)

key_store: KeyStore = FileSystemKeyStore("db")

challenge_solvers: List[ChallengeSolver] = []

# DNS Challenge Siolver
if os.getenv("CLOUDFLARE_API_TOKEN") is not None:
    challenge_solvers.append(CloudflareChallengeSolver())

http_challenge_solver = FilesystemChallengeSolver("acme-challenges")
challenge_solvers.append(http_challenge_solver)

cert_issuer = AcmeCertIssuer.with_keystore(key_store, http_challenge_solver)

cert_manager = AcmeCertManager(
    key_store=key_store,
    cert_issuer=cert_issuer,
    challenge_solvers=challenge_solvers,
    renew_threshold_days=int(os.getenv("CERT_RENEW_THRESHOLD_DAYS", 75)),
)
cert_manager.setup()

# Create namespaces for each blueprint
api_ns = Namespace("api", description="General API operations")
key_ns = Namespace("keys", description="Key management operations")
cert_ns = Namespace("certs", description="Certificate management operations")

api.add_namespace(api_ns)
api.add_namespace(key_ns)
api.add_namespace(cert_ns)


create_api_resources(api_ns, cert_manager, renew_queue_size=int(os.getenv("RENEW_QUEUE_SIZE", 5)))
create_key_resources(key_ns, key_store)
create_cert_resources(cert_ns, key_store)


@app.route("/.well-known/acme-challenge/<cid>", methods=["GET"])
def acme_challenge(cid):
    r = http_challenge_solver.get_challenge(cid)
    print(f"[{request.method}] /.well-known/acme-challenge/{cid} = {r}")
    if r is None:
        return "", 404
    return r, 200


@api.errorhandler(CertApiException)
def handle_certapi_error(error: CertApiException):
    print(f"CertApiException [{error.__class__.__name__}]: {error}", file=sys.stderr)
    print_filtered_traceback(error)

    status = 400
    if isinstance(error, AcmeHttpError):
        status = error.response.status_code
        if status == 200:
            status = 400

    return error.json_obj(), status


@api.errorhandler(RenewalQueueFullError)
def handle_renewal_queue_full_error(error: RenewalQueueFullError):
    return {"error": str(error)}, 429


@api.errorhandler(Exception)
def handle_generic_exception(error: Exception):
    print(f"Unhandled Exception: {error}", file=sys.stderr)
    traceback.print_exc(file=sys.stderr)
    return {"message": "Internal Server Error", "error": str(error)}, 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)
