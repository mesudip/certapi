import os
import sys
import traceback
from typing import List

from flask import Flask, jsonify, request
from flask_restx import Api, Namespace
from certapi.crypto.crypto_classes import Key
from certapi.server.api import create_api_resources
from certapi.server.key_api import create_key_resources
from certapi.server.cert_api import create_cert_resources
from certapi.acme.Acme import AcmeError, AcmeHttpError, AcmeNetworkError
from certapi.utils import print_filtered_traceback
from certapi.challenge_store import ChallengeStore, FileSystemChallengeStore
from certapi.challenge_store.dns.cloudflare.cloudflare_challenge_store import CloudflareChallengeStore
from certapi.keystore import KeyStore, FileSystemKeystore
from certapi.issuers import AcmeCertIssuer, SelfCertIssuer
from certapi.manager.acme_cert_manager import AcmeCertManager


app = Flask(__name__)
app.config["challenges"] = {}
app.config['RESTX_MASK_SWAGGER'] = False

# Initialize Flask-RESTX API
api = Api(app, version='1.0', title='CertManager API',
          description='A comprehensive API for managing SSL/TLS certificates.',
          doc='/swagger-ui')

key_store: KeyStore = FileSystemKeystore("db")

challenge_stores: List[ChallengeStore] = []

# HTTP Challenge Store


# DNS Challenge Stores
if os.getenv("CLOUDFLARE_API_TOKEN") is not None:
    challenge_stores.append(CloudflareChallengeStore())

http_challenge_store = FileSystemChallengeStore("acme-challenges")
challenge_stores.append(http_challenge_store)

# Create an account key if it doesn't exist
account_key = key_store.find_key_by_name("acme_account.key")
if account_key is None:
    account_key = Key.generate("ecdsa")
    key_store.save_key(account_key, "acme_account.key")

acme_issuer = AcmeCertIssuer(account_key=account_key, challenge_store=http_challenge_store) # AcmeCertIssuer expects a single challenge_store for its own use
self_issuer = SelfCertIssuer(account_key,country="NP",state="Bagmati",organization="Sireto Technology")
# acme_issuer.setup()

cert_manager = AcmeCertManager(key_store=key_store, cert_issuer=self_issuer, challenge_stores=challenge_stores)

# Create namespaces for each blueprint
api_ns = Namespace('api', description='General API operations')
key_ns = Namespace('keys', description='Key management operations')
cert_ns = Namespace('certs', description='Certificate management operations')

api.add_namespace(api_ns)
api.add_namespace(key_ns)
api.add_namespace(cert_ns)



create_api_resources(api_ns, cert_manager)
create_key_resources(key_ns, key_store)
create_cert_resources(cert_ns, key_store)


@app.route("/.well-known/acme-challenge/<cid>", methods=["GET"])
def acme_challenge(cid):
    r = http_challenge_store.get_challenge(cid)
    print(f"[{request.method}] /.well-known/acme-challenge/{cid} = {r}")
    return "", 404 if r is None else (r, 200)


@app.errorhandler(AcmeNetworkError)
def handle_acme_http_error(error: AcmeNetworkError):
    print(error.__class__.__name__, error, file=sys.stderr)
    print_filtered_traceback(error)
    return jsonify({"error": error.json_obj()}), 400


@app.errorhandler(AcmeHttpError)
def handle_acme_network_error(error: AcmeHttpError):
    print(error.__class__.__name__, error, file=sys.stderr)
    print_filtered_traceback(error)
    return jsonify({"error": error.json_obj()}), error.response.status_code

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081, threaded=True)