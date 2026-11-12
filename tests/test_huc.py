import unittest
from datetime import datetime, timedelta, timezone

from huc.certificate import issue_certificate, verify_certificate
from huc.crypto import generate_keypair
from huc.ledger import HucLedger, LedgerError


class HucCertificateTests(unittest.TestCase):
    def setUp(self):
        self.private_key, self.public_key = generate_keypair()
        self.ledger = HucLedger()
        self.certificate = issue_certificate(
            self.private_key, self.public_key, "test-subject-001",
            {"course": "HUC test course", "level": 1},
        )

    def test_valid_certificate_signature(self):
        self.assertTrue(verify_certificate(self.certificate))

    def test_tampered_claim_is_rejected(self):
        altered = {**self.certificate, "claims": {"course": "tampered"}}
        self.assertFalse(verify_certificate(altered))

    def test_wrong_issuer_key_is_rejected(self):
        _, other_public = generate_keypair()
        altered = {**self.certificate, "issuer": other_public}
        self.assertFalse(verify_certificate(altered))

    def test_issued_certificate_is_active(self):
        output_id = self.ledger.issue(self.certificate)
        self.assertTrue(self.ledger.verify_active(output_id))

    def test_revoked_certificate_is_not_active(self):
        output_id = self.ledger.issue(self.certificate)
        self.ledger.revoke(output_id, "test revocation")
        self.assertFalse(self.ledger.verify_active(output_id))

    def test_double_consumption_is_rejected(self):
        output_id = self.ledger.issue(self.certificate)
        self.ledger.revoke(output_id, "test revocation")
        with self.assertRaises(LedgerError):
            self.ledger.revoke(output_id, "second attempt")

    def test_duplicate_issuance_is_rejected(self):
        self.ledger.issue(self.certificate)
        with self.assertRaises(LedgerError):
            self.ledger.issue(self.certificate)

    def test_expired_certificate_is_not_active(self):
        expired = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        certificate = issue_certificate(self.private_key, self.public_key, "expired", {}, expired)
        output_id = self.ledger.issue(certificate)
        self.assertFalse(self.ledger.verify_active(output_id))


if __name__ == "__main__":
    unittest.main()
