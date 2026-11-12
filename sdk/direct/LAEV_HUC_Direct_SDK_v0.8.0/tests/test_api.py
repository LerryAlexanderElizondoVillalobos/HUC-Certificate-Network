from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path

try:
    from fastapi.testclient import TestClient
    API_AVAILABLE = True
except Exception:
    API_AVAILABLE = False

from huc_direct import HucIssuer, HucPresenter, generate_csr
from huc_direct.service import create_app


@unittest.skipUnless(API_AVAILABLE, "FastAPI/httpx optional dependencies are not installed")
class HucDirectApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.issuer, self.pin = HucIssuer.initialize(self.root / "issuer", "API-TEST-ISSUER")
        self.token = "z" * 48
        app = create_app(self.issuer, self.token, self.root / "replay-store.json")
        self.client = TestClient(app)
        self.csr, self.holder_private = generate_csr("API Test Holder", self.root / "holder")

    def tearDown(self):
        self.temp.cleanup()

    def test_health_and_public_trust_info(self):
        self.assertEqual(self.client.get("/healthz").status_code, 200)
        trust = self.client.get("/v1/trust").json()
        self.assertEqual(trust["trust_anchor_sha256"], self.pin)

    def test_issue_requires_admin_token_and_returns_bundle(self):
        payload = {"csr_pem": self.csr.read_text(), "days": 90}
        denied = self.client.post("/v1/credentials/issue", json=payload)
        self.assertEqual(denied.status_code, 401)
        issued = self.client.post("/v1/credentials/issue", json=payload,
                                  headers={"X-HUC-Admin-Token": self.token})
        self.assertEqual(issued.status_code, 200, issued.text)
        self.assertIn("credential_bundle_b64", issued.json())
        self.assertEqual(issued.json()["trust_anchor_sha256"], self.pin)

    def test_verify_challenge_and_direct_response_endpoints(self):
        issued = self.client.post("/v1/credentials/issue",
            json={"csr_pem": self.csr.read_text(), "days": 90},
            headers={"X-HUC-Admin-Token": self.token}).json()
        verified = self.client.post("/v1/credentials/verify",
            json={"bundle_b64": issued["credential_bundle_b64"]})
        self.assertEqual(verified.status_code, 200, verified.text)
        self.assertEqual(verified.json()["result"], "VALID")

        challenge_resp = self.client.post("/v1/direct/challenges", json={
            "certificate_sha256": issued["certificate_sha256"],
            "audience": "training.company.test", "ttl_seconds": 120})
        self.assertEqual(challenge_resp.status_code, 200, challenge_resp.text)
        challenge = challenge_resp.json()
        bundle = base64.b64decode(issued["credential_bundle_b64"])
        from huc_direct import HucVerifier
        response = HucPresenter.create_response(challenge, bundle, self.holder_private)
        direct = self.client.post("/v1/direct/verify", json={
            "challenge": challenge, "response": response, "audience": "training.company.test"})
        self.assertEqual(direct.status_code, 200, direct.text)
        self.assertEqual(direct.json()["result"], "VALID")
        replay = self.client.post("/v1/direct/verify", json={
            "challenge": challenge, "response": response, "audience": "training.company.test"})
        self.assertEqual(replay.status_code, 400)

    def test_renewal_endpoint_is_admin_protected_and_returns_new_bundle(self):
        issued = self.client.post("/v1/credentials/issue",
            json={"csr_pem": self.csr.read_text(), "days": 90},
            headers={"X-HUC-Admin-Token": self.token}).json()
        new_csr, _ = generate_csr("API Test Holder", self.root / "holder-renew")
        renewed = self.client.post("/v1/credentials/renew", json={
            "previous_certificate_pem": issued["certificate_pem"],
            "new_csr_pem": new_csr.read_text(), "days": 90},
            headers={"X-HUC-Admin-Token": self.token})
        self.assertEqual(renewed.status_code, 200, renewed.text)
        self.assertNotEqual(renewed.json()["certificate_sha256"], issued["certificate_sha256"])

    def test_refresh_endpoint_returns_current_status_bundle(self):
        issued = self.client.post("/v1/credentials/issue",
            json={"csr_pem": self.csr.read_text(), "days": 90},
            headers={"X-HUC-Admin-Token": self.token}).json()
        refreshed = self.client.post("/v1/credentials/refresh", json={
            "certificate_pem": issued["certificate_pem"]},
            headers={"X-HUC-Admin-Token": self.token})
        self.assertEqual(refreshed.status_code, 200, refreshed.text)
        self.assertEqual(refreshed.json()["status"], "ACTIVE")
        verified = self.client.post("/v1/credentials/verify", json={
            "bundle_b64": refreshed.json()["credential_bundle_b64"]})
        self.assertEqual(verified.json()["result"], "VALID")

    def test_revocation_endpoint_is_admin_protected(self):
        issued = self.client.post("/v1/credentials/issue",
            json={"csr_pem": self.csr.read_text(), "days": 90},
            headers={"X-HUC-Admin-Token": self.token}).json()
        denied = self.client.post("/v1/credentials/revoke", json={
            "certificate_pem": issued["certificate_pem"], "reason": "key-compromise"})
        self.assertEqual(denied.status_code, 401)
        revoked = self.client.post("/v1/credentials/revoke", json={
            "certificate_pem": issued["certificate_pem"], "reason": "key-compromise"},
            headers={"X-HUC-Admin-Token": self.token})
        self.assertEqual(revoked.status_code, 200, revoked.text)
        self.assertEqual(revoked.json()["status"], "REVOKED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
