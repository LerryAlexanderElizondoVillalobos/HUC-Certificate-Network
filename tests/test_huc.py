import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import huc


class HUCTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.workspace = self.root / "workspace"
        init = huc.initialize(self.workspace, threshold=2, authority_count=3)
        self.pin = init["trust_anchor_sha256"]
        self.requests = self.root / "requests"

    def tearDown(self):
        self.tmp.cleanup()

    def request(self, name="LAEV Test Subject"):
        result = huc.generate_request(self.requests, name)
        return Path(result["csr_file"]), Path(result["private_key_file"])

    def issue(self, name="LAEV Test Subject"):
        csr, private_key = self.request(name)
        result = huc.issue_csr(self.workspace, csr, 60)
        self.assertTrue(private_key.exists())
        return result

    def test_issue_creates_x509_cc_and_utxo(self):
        issued = self.issue()
        result = huc.verify_certificate(self.workspace, Path(issued["certificate_file"]),
                                        expected_anchor_sha256=self.pin)
        self.assertTrue(result["x509_signature_valid"])
        self.assertTrue(result["huc_cc_valid"])
        self.assertTrue(result["consensus_reached"])
        self.assertEqual(result["consensus_threshold"], 2)
        self.assertEqual(result["utxo_status"], "ACTIVE")
        self.assertTrue(result["hybrid_valid"])
        cc = json.loads(Path(issued["consensus_certificate_file"]).read_text())
        self.assertEqual(cc["type"], huc.CC_TYPE)
        self.assertEqual(len(cc["signatures"]), 2)

    def test_insufficient_consensus_signatures_rejected(self):
        csr, _ = self.request()
        with self.assertRaisesRegex(ValueError, "umbral de firmas"):
            huc.issue_csr(self.workspace, csr, 60, signer_ids=["HUC-AUTH-01"])
        state = huc.audit(self.workspace, self.pin)
        self.assertEqual(state["event_count"], 0)

    def test_renew_consumes_old_utxo_and_creates_new_one(self):
        old = self.issue()
        new_csr, _ = self.request()
        renewed = huc.renew_csr(self.workspace, Path(old["certificate_file"]), new_csr, 60)
        old_check = huc.verify_certificate(self.workspace, Path(old["certificate_file"]),
                                           expected_anchor_sha256=self.pin)
        new_check = huc.verify_certificate(self.workspace, Path(renewed["certificate_file"]),
                                           expected_anchor_sha256=self.pin)
        self.assertEqual(old_check["utxo_status"], "SUPERSEDED")
        self.assertFalse(old_check["hybrid_valid"])
        self.assertEqual(new_check["utxo_status"], "ACTIVE")
        self.assertTrue(new_check["hybrid_valid"])

    def test_revoke_consumes_active_utxo(self):
        issued = self.issue()
        result = huc.revoke(self.workspace, Path(issued["certificate_file"]), "key-compromise")
        checked = huc.verify_certificate(self.workspace, Path(issued["certificate_file"]),
                                         expected_anchor_sha256=self.pin)
        self.assertEqual(result["status"], "REVOKED")
        self.assertEqual(checked["utxo_status"], "REVOKED")
        self.assertFalse(checked["hybrid_valid"])

    def test_duplicate_json_properties_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "Propiedad JSON duplicada"):
            huc.strict_json_loads('{"action":"ISSUE","action":"REVOKE"}')

    def test_wrong_external_trust_pin_rejected(self):
        with self.assertRaisesRegex(ValueError, "no coincide"):
            huc.audit(self.workspace, "0" * 64)

    def test_tampered_consensus_certificate_rejected(self):
        issued = self.issue()
        cc_path = Path(issued["consensus_certificate_file"])
        cc = json.loads(cc_path.read_text())
        cc["payload"]["authorized_state_at_issuance"] = "REVOKED"
        cc_path.write_text(json.dumps(cc))
        with self.assertRaisesRegex(ValueError, "Consenso insuficiente"):
            huc.verify_certificate(self.workspace, Path(issued["certificate_file"]),
                                   expected_anchor_sha256=self.pin)

    def test_tampered_ledger_rejected(self):
        self.issue()
        path = self.workspace / huc.LEDGER_FILE
        event = json.loads(path.read_text().splitlines()[0])
        event["payload"]["action"] = "REVOKE"
        path.write_text(json.dumps(event) + "\n")
        with self.assertRaisesRegex(ValueError, "Ledger inválido"):
            huc.audit(self.workspace, self.pin)

    def test_bundle_verifies_without_private_keys(self):
        issued = self.issue()
        bundle = self.root / "public-package.zip"
        huc.export_bundle(self.workspace, Path(issued["certificate_file"]), bundle)
        result = huc.verify_bundle(bundle, self.pin)
        self.assertTrue(result["package_verified"])
        self.assertTrue(result["hybrid_valid"])
        import zipfile
        with zipfile.ZipFile(bundle) as zf:
            names = zf.namelist()
        self.assertFalse(any("private" in name.lower() or name.endswith(".key") for name in names))

    def test_wrong_certificate_cc_binding_rejected(self):
        first = self.issue("Person One")
        second = self.issue("Person Two")
        with self.assertRaisesRegex(ValueError, "no está vinculado"):
            huc.verify_certificate(self.workspace, Path(second["certificate_file"]),
                                   Path(first["consensus_certificate_file"]), self.pin)

    def test_double_spend_attempt_only_one_transition_wins(self):
        issued = self.issue()
        digest = issued["certificate_sha256_der"]
        outpoint = issued["utxo_outpoint"]
        def attempt(_):
            try:
                huc._append_transition(self.workspace, "REVOKE", digest,
                    previous_outpoint=outpoint, reason="concurrency-test")
                return "accepted"
            except ValueError:
                return "rejected"
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, range(2)))
        self.assertEqual(results.count("accepted"), 1)
        self.assertEqual(results.count("rejected"), 1)
        self.assertEqual(huc.audit(self.workspace, self.pin)["statuses"][digest], "REVOKED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
