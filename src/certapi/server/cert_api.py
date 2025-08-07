from flask import jsonify, request
import os
from flask_restx import Resource, fields, reqparse
from certapi.crypto.crypto import cert_to_pem, certs_to_pem
from cryptography.x509 import Certificate


def create_cert_resources(cert_ns, key_store):

    cert_model = cert_ns.model(
        "Certificate",
        {
            "id": fields.String(description="The certificate identifier"),
            "key_id": fields.String(description="The associated key identifier"),
            "pem": fields.String(description="The PEM encoded certificate"),
        },
    )

    cert_input_model = cert_ns.model(
        "CertificateInput",
        {
            "private_key_id": fields.String(
                required=True, description="ID of the private key associated with the certificate"
            ),
            "cert": fields.String(required=True, description="PEM encoded certificate string"),
            "domains": fields.List(
                fields.String, required=True, description="List of domains covered by the certificate"
            ),
            "name": fields.String(description="Optional name for the certificate"),
        },
    )

    # Parser for /certs endpoint with optional domain filter
    cert_list_parser = reqparse.RequestParser()
    cert_list_parser.add_argument("domain", type=str, help="Filter certificates by domain")

    @cert_ns.route("/certs")
    class CertList(Resource):
        @cert_ns.doc("list_certs")
        @cert_ns.expect(cert_list_parser)
        @cert_ns.marshal_list_with(cert_model)
        def get(self):
            args = cert_list_parser.parse_args()
            domain = args["domain"]

            if domain:
                cert_info = key_store.find_key_and_cert_by_domain(domain)
                if cert_info:
                    key_id, key_obj, cert_list = cert_info
                    if isinstance(cert_list, list):
                        pem_content = certs_to_pem(cert_list).decode("utf-8")
                    else:
                        pem_content = (
                            cert_to_pem(cert_list).decode("utf-8") if hasattr(cert_list, "public_bytes") else cert_list
                        )

                    return [
                        {"id": domain, "key_id": key_id, "pem": pem_content}  # Using domain as ID for this endpoint
                    ]
                else:
                    cert_ns.abort(404, message="Certificate not found for this domain")
            else:
                certs = key_store.list_certs()
                cert_data = []
                for cert_id, cert_info in certs.items():
                    # cert_info is a tuple: (key_id, key_obj, cert_list)
                    cert_list = cert_info[2]
                    if isinstance(cert_list, list):
                        pem_content = certs_to_pem(cert_list).decode("utf-8")
                    else:  # Assuming it's already a single Certificate object or PEM string
                        pem_content = (
                            cert_to_pem(cert_list).decode("utf-8") if hasattr(cert_list, "public_bytes") else cert_list
                        )

                    cert_data.append({"id": cert_id, "key_id": cert_info[0], "pem": pem_content})
                return cert_data

        @cert_ns.doc("create_cert")
        @cert_ns.expect(cert_input_model, validate=True)
        @cert_ns.marshal_with(cert_model, code=201)
        def post(self):
            if os.getenv("ENABLE_KEYSTORE_EDIT") != "true":
                cert_ns.abort(403, "Key store editing is not enabled")

            data = request.get_json()
            try:
                private_key_id = data["private_key_id"]
                cert_pem = data["cert"]
                domains = data["domains"]
                name = data.get("name")

                cert_id = key_store.save_cert(private_key_id, cert_pem, domains, name)
                return {"id": cert_id, "key_id": private_key_id, "pem": cert_pem}, 201
            except Exception as e:
                cert_ns.abort(500, f"Error saving certificate: {e}")

    @cert_ns.route("/certs/<string:cert_id>")
    @cert_ns.param("cert_id", "The certificate identifier")
    class CertById(Resource):
        @cert_ns.doc("get_cert_by_id")
        @cert_ns.marshal_with(cert_model)
        @cert_ns.response(404, "Certificate not found")
        def get(self, cert_id):
            cert_info = key_store.find_key_and_cert_by_cert_id(cert_id)
            if cert_info:
                key_obj, cert_list = cert_info
                if isinstance(cert_list, list):
                    pem_content = certs_to_pem(cert_list).decode("utf-8")
                else:
                    pem_content = (
                        cert_to_pem(cert_list).decode("utf-8") if hasattr(key_obj, "public_bytes") else cert_list
                    )

                return {
                    "id": cert_id,
                    "key_id": (
                        key_obj.id if hasattr(key_obj, "id") else None
                    ),  # Assuming Key object has an 'id' attribute
                    "pem": pem_content,
                }
            else:
                cert_ns.abort(404, message="Certificate not found")
