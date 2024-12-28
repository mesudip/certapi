import sys

from flask import Flask, request, jsonify
from certmanager import challenge, CertAuthority, crypto
from certmanager.Acme import AcmeError
from certmanager.challenge import challenge_store
from certmanager.db import SqliteKeyStore, FilesystemKeyStore

app = Flask(__name__)
app.config["challenges"] = {}

key_store = FilesystemKeyStore("db")

certAuthority = CertAuthority(challenge_store, key_store)


@app.route("/obtain", methods=["GET"])
def obtain_cert():
    hostnames = []
    try:
        hostnames = request.args.getlist("hostname")
    except TypeError:
        hostnames = request.args.get("hostname")
    data, error = certAuthority.obtainCert(hostnames)

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
    elif error:
        return jsonify(error.json()), error.status_code
    else:
        return jsonify({"message": "something went wrong"}), 500


@app.route("/list", methods=["GET"])
def list_certs():
    return jsonify(
        {
            "username": "sudip",
            "theme": "light",
            "k2": "v",
        }
    )


@app.route("/.well-known/acme-challenge/<cid>", methods=["GET"])
def acme_challenge(cid):
    r = challenge_store.get_challenge(cid)
    print(f"[{request.method}] /.well-known/acme-challenge/{cid} = {r}")
    return "", 404 if r is None else (r, 200)


@app.errorhandler(AcmeError)
def handle_acme_error(error):
    print(error, file=sys.stderr)
    return jsonify({"error": error.jsonObj()}), 500


# @app.errorhandler(Exception)
# def handle_generic_error(error):
#     return jsonify({"error": str(error)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)
