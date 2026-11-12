from __future__ import annotations

import base64
import json
import tempfile
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from huc_direct import HucIssuer, HucPresenter, HucVerifier, generate_csr
from huc_direct.core import read_json, write_json, sha256, object_hash


class HucDirectSdkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.issuer, self.pin = HucIssuer.initialize(self.root / "issuer", "TEST-ISSUER", 600)
        csr, self.holder_private = generate_csr("SDK Test Holder", self.root / "holder")
        self.credential = self.issuer.issue(csr.read_bytes(), 90)
        self.verifier = HucVerifier(self.pin, max_state_age_seconds=600)
        self.bundle = self.credential.bundle

    def tearDown(self):
        self.temp.cleanup()

    def test_issue_and_offline_verify(self):
        result = self.verifier.verify_bundle(self.bundle)
        self.assertEqual(result["result"], "VALID")
        self.assertTrue(result["x509_signature_valid"])
        self.assertTrue(result["huc_cc_signature_valid"])
        self.assertTrue(result["issuer_state_signature_valid"])
        self.assertEqual(result["utxo_status"], "ACTIVE")

    def test_external_trust_pin_is_required(self):
        with self.assertRaisesRegex(ValueError, "pin mismatch"):
            HucVerifier("0" * 64).verify_bundle(self.bundle)

    def test_huc_cc_tampering_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with zipfile.ZipFile(self._bundle_file()) as zf:
                zf.extractall(root)
            cc = read_json(root / "consensus_certificate.json")
            cc["payload"]["consensus_mode"] = "FAKE"
            write_json(root / "consensus_certificate.json", cc)
            manifest = read_json(root / "package_manifest.json")
            manifest["consensus_certificate_sha256"] = object_hash(cc)
            write_json(root / "package_manifest.json", manifest)
            bad_bundle = self.root / "bad-cc.zip"
            self._zip_dir(root, bad_bundle)
            with self.assertRaisesRegex(ValueError, "HUC-CC id|signature"):
                self.verifier.verify_bundle(bad_bundle)

    def test_attestation_tampering_rejected_even_if_manifest_updated(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with zipfile.ZipFile(self._bundle_file()) as zf:
                zf.extractall(root)
            att = read_json(root / "state_attestation.json")
            att["payload"]["status"] = "REVOKED"
            write_json(root / "state_attestation.json", att)
            manifest = read_json(root / "package_manifest.json")
            manifest["state_attestation_sha256"] = sha256((root / "state_attestation.json").read_bytes())
            write_json(root / "package_manifest.json", manifest)
            bad_bundle = self.root / "bad-state.zip"
            self._zip_dir(root, bad_bundle)
            with self.assertRaisesRegex(ValueError, "Invalid Ed25519 signature"):
                self.verifier.verify_bundle(bad_bundle)

    def test_renewal_consumes_old_utxo(self):
        csr, _ = generate_csr("SDK Test Holder", self.root / "holder-renewed")
        renewed = self.issuer.renew(self.credential.certificate_pem, csr.read_bytes(), 90)
        new_check = self.verifier.verify_bundle(renewed.bundle)
        old_bundle = self.issuer.create_bundle(self._persist_cert(self.credential.certificate_pem))
        old_check = self.verifier.verify_bundle(old_bundle)
        self.assertEqual(new_check["utxo_status"], "ACTIVE")
        self.assertEqual(old_check["utxo_status"], "SUPERSEDED")
        self.assertEqual(old_check["result"], "INVALID")

    def test_revocation_consumes_current_utxo(self):
        result = self.issuer.revoke(self.credential.certificate_pem, "key-compromise")
        check = self.verifier.verify_bundle(result["bundle"])
        self.assertEqual(check["utxo_status"], "REVOKED")
        self.assertEqual(check["result"], "INVALID")

    def test_direct_challenge_response_and_replay_protection(self):
        challenge = self.verifier.create_challenge(self.credential.certificate_sha256, "hr.example.test")
        response = HucPresenter.create_response(challenge, self.bundle, self.holder_private)
        proof = self.verifier.verify_response(response, challenge, "hr.example.test", self.root / "replay.json")
        self.assertEqual(proof["result"], "VALID")
        self.assertTrue(proof["holder_proof_of_possession"])
        with self.assertRaisesRegex(ValueError, "replay"):
            self.verifier.verify_response(response, challenge, "hr.example.test", self.root / "replay.json")

    def test_direct_challenge_audience_mismatch_rejected(self):
        challenge = self.verifier.create_challenge(self.credential.certificate_sha256, "student-portal.example")
        response = HucPresenter.create_response(challenge, self.bundle, self.holder_private)
        with self.assertRaisesRegex(ValueError, "audience mismatch"):
            self.verifier.verify_response(response, challenge, "different.example", self.root / "replay.json")

    def test_holder_key_mismatch_rejected(self):
        challenge = self.verifier.create_challenge(self.credential.certificate_sha256, "example.test")
        _, other_key = generate_csr("Other holder", self.root / "other-holder")
        with self.assertRaisesRegex(ValueError, "does not match"):
            HucPresenter.create_response(challenge, self.bundle, other_key)

    def test_response_tampering_rejected(self):
        challenge = self.verifier.create_challenge(self.credential.certificate_sha256, "example.test")
        response = HucPresenter.create_response(challenge, self.bundle, self.holder_private)
        response["holder_signature_b64"] = base64.b64encode(b"x" * 128).decode()
        with self.assertRaisesRegex(ValueError, "proof-of-possession"):
            self.verifier.verify_response(response, challenge, "example.test", self.root / "replay.json")

    def test_stale_state_receipt_returns_indeterminate(self):
        from datetime import timedelta
        import zipfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with zipfile.ZipFile(self._bundle_file()) as zf:
                zf.extractall(root)
            att = read_json(root / "state_attestation.json")
            old = __import__("datetime").datetime.now(__import__("datetime").timezone.utc) - timedelta(hours=1)
            issued_at = old.replace(microsecond=0)
            ttl = 600
            att["payload"]["issued_at_utc"] = issued_at.isoformat().replace("+00:00", "Z")
            att["payload"]["expires_at_utc"] = (issued_at + timedelta(seconds=ttl)).isoformat().replace("+00:00", "Z")
            issuer_key = __import__("huc_direct.core", fromlist=["load_private", "_sign_ed"])
            att["signature"] = issuer_key._sign_ed(
                issuer_key.load_private(self.issuer.workspace / "issuer_private.pem"), att["payload"])
            write_json(root / "state_attestation.json", att)
            manifest = read_json(root / "package_manifest.json")
            manifest["state_attestation_sha256"] = sha256((root / "state_attestation.json").read_bytes())
            write_json(root / "package_manifest.json", manifest)
            stale_zip = self.root / "stale.zip"
            self._zip_dir(root, stale_zip)
            result = self.verifier.verify_bundle(stale_zip)
            self.assertEqual(result["result"], "INDETERMINATE")
            self.assertFalse(result["state_freshness_valid"])

    def test_concurrent_revocations_only_one_consumes_utxo(self):
        def attempt(_):
            try:
                self.issuer.revoke(self.credential.certificate_pem, "concurrent-revoke")
                return "ok"
            except ValueError:
                return "rejected"
        with ThreadPoolExecutor(max_workers=2) as pool:
            outputs = list(pool.map(attempt, range(2)))
        self.assertEqual(outputs.count("ok"), 1)
        self.assertEqual(outputs.count("rejected"), 1)

    def test_public_credential_bundle_contains_no_private_keys(self):
        with zipfile.ZipFile(self._bundle_file()) as zf:
            for name in zf.namelist():
                self.assertNotIn("private", name.lower())
                self.assertNotIn(b"BEGIN PRIVATE KEY", zf.read(name))

    def _bundle_file(self) -> Path:
        path = self.root / "credential.zip"
        path.write_bytes(self.bundle)
        return path

    @staticmethod
    def _zip_dir(root: Path, output: Path) -> None:
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in root.iterdir():
                if path.is_file():
                    zf.write(path, path.name)

    def _persist_cert(self, cert_pem: bytes) -> Path:
        path = self.root / "previous-certificate.pem"
        path.write_bytes(cert_pem)
        return path


if __name__ == "__main__":
    unittest.main(verbosity=2)
