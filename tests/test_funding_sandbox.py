import unittest

from validation.huc_funding_sandbox import FundingSandbox


class FundingSandboxTests(unittest.TestCase):
    def setUp(self):
        self.sandbox = FundingSandbox()

    def make_intent(self, amount="25.00"):
        return self.sandbox.create_intent(
            reference_id="HUC-DEMO-CONTRIBUTION-001",
            amount=amount,
            currency="USD",
            idempotency_key="intent-001",
            certificate_sha256="a" * 64,
        )

    def test_authorize_capture_and_replay_are_idempotent(self):
        intent = self.make_intent()
        self.assertEqual(intent["status"], "created")
        self.sandbox.authorize(intent["intent_id"])
        captured = self.sandbox.capture(intent["intent_id"])
        replay = self.sandbox.capture(intent["intent_id"])
        self.assertEqual(captured["status"], "captured")
        self.assertEqual(replay["captured_amount"], "25.00")
        self.assertEqual(self.sandbox.synthetic_balance, "25.00")

    def test_partial_and_full_refund_preserve_balance(self):
        intent = self.make_intent()
        self.sandbox.authorize(intent["intent_id"])
        self.sandbox.capture(intent["intent_id"])
        partial = self.sandbox.refund(intent["intent_id"], amount="5.00", idempotency_key="refund-1")
        self.assertEqual(partial["status"], "partially_refunded")
        final = self.sandbox.refund(intent["intent_id"], amount="20.00", idempotency_key="refund-2")
        self.assertEqual(final["status"], "refunded")
        self.assertEqual(self.sandbox.synthetic_balance, "0.00")

    def test_refund_cannot_exceed_captured_amount(self):
        intent = self.make_intent()
        self.sandbox.authorize(intent["intent_id"])
        self.sandbox.capture(intent["intent_id"])
        with self.assertRaisesRegex(ValueError, "exceeds remaining"):
            self.sandbox.refund(intent["intent_id"], amount="25.01", idempotency_key="refund-too-large")

    def test_capture_requires_authorization(self):
        intent = self.make_intent()
        with self.assertRaisesRegex(ValueError, "authorized"):
            self.sandbox.capture(intent["intent_id"])

    def test_idempotency_key_cannot_change_request(self):
        self.make_intent()
        with self.assertRaisesRegex(ValueError, "different request"):
            self.sandbox.create_intent(
                reference_id="HUC-DEMO-CONTRIBUTION-001",
                amount="26.00",
                currency="USD",
                idempotency_key="intent-001",
            )

    def test_invalid_credential_reference_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "32-byte hexadecimal"):
            self.sandbox.create_intent(
                reference_id="HUC-DEMO-CONTRIBUTION-002",
                amount="1.00",
                idempotency_key="intent-002",
                certificate_sha256="not-a-hash",
            )

    def test_evidence_contains_verifiable_hash_chain(self):
        intent = self.make_intent()
        self.sandbox.authorize(intent["intent_id"])
        self.sandbox.capture(intent["intent_id"])
        evidence = self.sandbox.evidence()
        self.assertTrue(evidence["event_chain_valid"])
        self.assertEqual(evidence["event_count"], 3)
        self.assertEqual(evidence["mode"], "SYNTHETIC_NO_EXTERNAL_PROVIDER")


if __name__ == "__main__":
    unittest.main(verbosity=2)
