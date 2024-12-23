import json
import base64
from typing import Union


def b64_encode(data: Union[str, bytes, bytearray, dict, list]) -> bytes:
    if type(data) in (dict, list):
        data = json.dumps(data).encode("utf-8")
    elif type(data) == str:
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def b64_string(data: Union[str, bytes, bytearray, dict, list]) -> str:
    return b64_encode(data).decode("utf-8")


def crypto():
    return None
