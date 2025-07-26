import os
import sys
import traceback

from flask import Flask, request, jsonify
from certapi import CertAuthority
from certapi.acme.Acme import AcmeError, AcmeHttpError, AcmeNetworkError
from certapi.challenge_store.ChallengeStore import challenge_store
from certapi.challenge_store import ChallengeStore
from certapi.dns_providers.cloudflare.cloudflare_challenge_store import CloudflareChallengeStore
from certapi.crypto import crypto
from certapi.keystore.KeyStore import SqliteKeyStore, FilesystemKeyStore
from certapi.utils import print_filtered_traceback

app = Flask(__name__)
app.config["challenges"] = {}

key_store = FilesystemKeyStore("db")
dns_stores = []
if os.getenv("CLOUDFLARE_API_TOKEN") is not None:
    dns_stores.append(CloudflareChallengeStore())
certAuthority = CertAuthority(challenge_store, key_store, dns_stores=dns_stores)
certAuthority.setup()


@app.route("/obtain", methods=["GET"])
def obtain_cert():
    hostnames = []
    try:
        hostnames = request.args.getlist("hostname")
    except TypeError:
        hostnames = request.args.get("hostname")

    data = certAuthority.obtainCert(hostnames)

    if data:
        return jsonify(
            data.__json__()
            # {
            #     "existing": existing,
            #     "new": {
            #         "domains": missing,
            #         "subject": missing[0],
            #         "private_key": crypto.key_to_pem(private_key).decode("utf-8") if private_key else None,
            #         "certificate": (
            #             certificate.public_bytes(crypto.serialization.Encoding.PEM).decode("utf-8")
            #             if certificate
            #             else None
            #         ),
            #     },
            # }
        )
        # else:
        #     return jsonify({"existing": existing, "new": {"domains": []}})
    else:
        return jsonify({"message": "something went wrong"}), 500



@app.route("/.well-known/acme-challenge/<cid>", methods=["GET"])
def acme_challenge(cid):
    r = challenge_store.get_challenge(cid)
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
    app.run(host="0.0.0.0", port=8082, threaded=True)
