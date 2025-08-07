from flask import jsonify, request
import os
from flask_restx import Resource, fields, reqparse
from certapi.crypto.crypto import key_to_pem
from certapi.crypto.crypto_classes import Key


def create_key_resources(key_ns, key_store):

    key_model = key_ns.model(
        "Key",
        {
            "id": fields.String(description="The key identifier"),
            "pem": fields.String(description="The PEM encoded key"),
        },
    )

    key_input_model = key_ns.model(
        "KeyInput",
        {
            "name": fields.String(required=True, description="Name of the key"),
            "pem": fields.String(required=True, description="PEM encoded key string"),
        },
    )

    @key_ns.route("/keys")
    class KeyList(Resource):
        @key_ns.doc("list_keys")
        @key_ns.marshal_list_with(key_model)
        def get(self):
            keys = key_store.list_keys()
            key_data = []
            for key_id, key_obj in keys.items():
                key_data.append({"id": key_id, "pem": key_to_pem(key_obj).decode("utf-8")})
            return key_data

        @key_ns.doc("create_key")
        @key_ns.expect(key_input_model, validate=True)
        @key_ns.marshal_with(key_model, code=201)
        def post(self):
            if os.getenv("ENABLE_KEYSTORE_EDIT") != "true":
                key_ns.abort(403, "Key store editing is not enabled")

            data = request.get_json()
            try:
                key_obj = Key.from_pem(data["pem"].encode("utf-8"))
                key_id = key_store.save_key(key_obj, data["name"])
                return {"id": key_id, "pem": data["pem"]}, 201
            except Exception as e:
                key_ns.abort(500, f"Error saving key: {e}")

    @key_ns.route("/keys/<string:key_id>")
    @key_ns.param("key_id", "The key identifier")
    class KeyById(Resource):
        @key_ns.doc("get_key_by_id")
        @key_ns.marshal_with(key_model)
        @key_ns.response(404, "Key not found")
        def get(self, key_id):
            key_obj = key_store.find_key_by_id(key_id)
            if key_obj:
                return {"id": key_id, "pem": key_to_pem(key_obj).decode("utf-8")}
            else:
                key_ns.abort(404, message="Key not found")

    @key_ns.route("/keys/name/<string:name>")
    @key_ns.param("name", "The key name")
    class KeyByName(Resource):
        @key_ns.doc("get_key_by_name")
        @key_ns.marshal_with(key_model)
        @key_ns.response(404, "Key not found")
        def get(self, name):
            key_obj = key_store.find_key_by_name(name)
            if key_obj:
                return {"id": name, "pem": key_to_pem(key_obj).decode("utf-8")}
            else:
                key_ns.abort(404, message="Key not found")
