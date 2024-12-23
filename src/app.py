from sanic.handlers import ErrorHandler

from certmanager import challenge, CertAuthority, crypto

from sanic import Sanic
from sanic.response import json, text
from sanic.request import Request

app = Sanic(name="certManager")
app.ctx.challenges = {}


def addChallenge(k, v):
    app.ctx.challenges[k] = v


app.ctx.certAuthority: CertAuthority = CertAuthority(addChallenge)


@app.route("/obtain")
async def home(request: Request):
    data, error = app.ctx.certAuthority.obtainCert(request.args.getlist("hostname"))
    if data:
        (existing, missing, private_key, certificate) = data
        if len(missing):
            return json(
                {
                    "existing": existing,
                    "new": {
                        "domains": missing,
                        "subject": missing[0],
                        "private_key": crypto.key_to_pem(private_key).decode("utf-8") if private_key else None,
                        "certificate": (
                            certificate.public_bytes(crypto.serialization.Encoding.PEM).decode("utf-8")
                            if certificate
                            else None
                        ),
                    },
                }
            )
        else:
            return json({"existing": existing, "new": {"domains": []}})
    elif error:
        return json(error.json(), error.status_code)
    else:
        return json({"message": "something went wrong"}, 500)


@app.route("/list")
async def list_certs(request: Request):
    return json(
        {
            "username": "sudip",
            "theme": "light",
            "k2": "v",
            # "image": url_for("user_image", filename="sudip"),
        }
    )


@app.route("/.well-known/acme-challenge/<cid>")
async def acme_challenge(req: Request, cid):
    r = app.ctx.challenges.get(req)

    print("[", req.method, "] /.well-known/acme-challenge/" + cid, "=", r)
    return text("", 404) if r is None else text(r)


class CustomErrorHandler(ErrorHandler):
    def default(self, request, exception):
        """handles errors that have no error handlers assigned"""
        # You custom error handling logic...
        return super().default(request, exception)


app.error_handler = CustomErrorHandler()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, workers=3)
