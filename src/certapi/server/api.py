import json
from flask import request, jsonify
from cryptography.x509 import CertificateSigningRequest
from flask_restx import Resource, reqparse, fields

from certapi import AcmeCertManager


def create_api_resources(api_ns, cert_manager: AcmeCertManager):

    # Models for documentation
    issued_cert_model = api_ns.model(
        "IssuedCertData",
        {
            "privateKey": fields.String(description="PEM encoded private key"),
            "certificate": fields.String(description="PEM encoded certificate"),
            "domains": fields.List(fields.String, description="List of domains covered by the certificate"),
        },
    )

    certificate_response_model = api_ns.model(
        "CertificateResponseData",
        {
            "existing": fields.List(fields.Nested(issued_cert_model), description="List of existing certificates"),
            "issued": fields.List(fields.Nested(issued_cert_model), description="List of newly issued certificates"),
        },
    )

    error_model = api_ns.model(
        "Error",
        {
            "message": fields.String(description="Error message"),
        },
    )

    # Parser for /obtain endpoint
    obtain_parser = reqparse.RequestParser()
    obtain_parser.add_argument(
        "hostname", type=str, action="append", required=True, help="List of hostnames for the certificate"
    )
    obtain_parser.add_argument("key_type", type=str, default="rsa", help="Type of key (rsa or ecdsa)")
    obtain_parser.add_argument("expiry_days", type=int, default=90, help="Number of days until certificate expiry")
    obtain_parser.add_argument("country", type=str, help="Country name")
    obtain_parser.add_argument("state", type=str, help="State or province name")
    obtain_parser.add_argument("locality", type=str, help="Locality name")
    obtain_parser.add_argument("organization", type=str, help="Organization name")
    obtain_parser.add_argument("user_id", type=str, help="User ID")

    @api_ns.route("/obtain")
    class ObtainCert(Resource):
        @api_ns.doc(
            parser=obtain_parser,
            responses={
                200: ("Certificate obtained successfully", certificate_response_model),
                500: ("Internal server error", error_model),
            },
        )
        def get(self):
            args = obtain_parser.parse_args()
            hostnames = args["hostname"]

            data = cert_manager.issue_certificate(
                hostnames,
                key_type=args["key_type"],
                expiry_days=args["expiry_days"],
                country=args["country"],
                state=args["state"],
                locality=args["locality"],
                organization=args["organization"],
                user_id=args["user_id"],
            )
            print(data)
            print(data.to_json())
            if data:
                return data.to_json()
            else:
                api_ns.abort(500, message="something went wrong")

    @api_ns.route("/sign_csr")
    class SignCsr(Resource):
        @api_ns.doc(
            description="Signs a Certificate Signing Request (CSR)",
            responses={200: "CSR signed successfully", 400: "Invalid CSR", 500: "Failed to sign CSR"},
        )
        @api_ns.expect(
            api_ns.model("CSR", {"csr_pem": fields.String(required=True, description="PEM encoded CSR")}), validate=True
        )
        def post(self):
            try:
                csr_pem = request.data.decode("utf-8")
                csr = CertificateSigningRequest.from_pem(csr_pem.encode("utf-8"))

                signed_cert_pem = cert_manager.issue_certificate_for_csr(csr)

                if signed_cert_pem:
                    return signed_cert_pem, 200, {"Content-Type": "application/x-pem-file"}
                else:
                    api_ns.abort(500, message="Failed to sign CSR")
            except ValueError as e:
                api_ns.abort(400, message=str(e))
            except Exception as e:
                print(f"Error signing CSR: {e}")
                api_ns.abort(500, message="An unexpected error occurred")
