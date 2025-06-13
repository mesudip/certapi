import os
import sys
import traceback

from flask import Flask, request, jsonify
from certapi import challenge, CertAuthority, crypto
from certapi.Acme import AcmeError
from certapi.challenge import challenge_store
from certapi.cloudflare_challenge_store import CloudflareChallengeStore
from certapi.db import SqliteKeyStore, FilesystemKeyStore

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
def handle_acme_error(error: AcmeError):
    print(error.__class__.__name__, error, file=sys.stderr)
    print_filtered_traceback(error)
    return jsonify({"error": error.json_obj()}), 500


def print_filtered_traceback(error, package_name="certapi"):
    """
    Prints the stack trace, stopping at the specified package,
    and excluding functions with names starting with '_'.

    :param error: The exception object.
    :param package_name: The package name to filter the trace.
    """
    tb = error.__traceback__
    filtered_tb = []

    while tb is not None:
        frame = tb.tb_frame
        function_name = frame.f_code.co_name
        if package_name in frame.f_globals.get("__name__", "") and not function_name.startswith("_"):
            filtered_tb.append(tb)
        tb = tb.tb_next

    if filtered_tb:
        print(f"Filtered traceback (up to package '{package_name}'):", file=sys.stderr)
        for tb in filtered_tb:
            frame = tb.tb_frame
            function_name = frame.f_code.co_name

            # Filter the actual stack trace to ensure no private functions appear
            if not function_name.startswith("_"):
                traceback.print_tb(tb, file=sys.stderr)
    else:
        print(f"No matching frames found in traceback for package '{package_name}'.", file=sys.stderr)


# @app.errorhandler(Exception)
# def handle_generic_error(error):
#     return jsonify({"error": str(error)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8082, threaded=True)
