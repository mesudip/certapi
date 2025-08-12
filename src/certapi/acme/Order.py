from typing import List, Tuple
from certapi.crypto import crypto, csr_to_der
from certapi.util import b64_string
from cryptography.x509 import CertificateSigningRequest, Certificate
from .Challenge import *
from .http import get


class Order:
    def __init__(self, url, data, challenges, acme):
        self.url = url
        self._data = data
        self.all_challenges = challenges
        self._acme = acme
        self.status = "pending"

    def remaining_challenges(self) -> List["Challenge"]:
        return [x for x in self.all_challenges if not x.verified]

    def refresh(self):
        response = get("Fetch order Status", self.url)
        self._data = response.json()
        self.status = self._data["status"]
        return response

    def get_certificate(self) -> str:
        if self.status == "processing":
            raise ValueError(
                "Order is still in 'processing' state! Wait until the order is finalized, and  call `Order.refresh()`  to update the state"
            )
        elif self.status != "valid":
            raise ValueError("Order not in 'valid' state! Complete challenge and call finalize()")

        certificate_res = self._acme._signed_req(self._data["certificate"], step="Download Certificate")
        return certificate_res.text

    def finalize(self, csr: CertificateSigningRequest):
        """
        Finalizes the order with the provided CSR.

        :param csr: The Certificate Signing Request (CSR) to be used for finalizing the order.
        """
        finalized = self._acme._signed_req(
            self._data["finalize"], {"csr": b64_string(csr_to_der(csr))}, step="Order Finalize"
        )
        finalized_json = finalized.json()
        self._data = finalized_json
        self.status = finalized_json["status"]
