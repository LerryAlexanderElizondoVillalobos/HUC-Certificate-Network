"""Four-organization institutional rehearsal for the Linux reference implementation.

This is an automated integration rehearsal with four separately generated authority
keys and isolated workspaces. It is not evidence that external institutions have
participated or that the BFT network has been deployed across four hosts.
"""
import tempfile
import unittest
from pathlib import Path

import huc
import huc_federation as fed


class FourInstitutionPilotRehearsal(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="huc-four-institutions-")
        self.root = Path(self.tmp.name)
        self.issuer = self.root / "issuer"
        self.authorities = {}
        descriptors = []

        for authority_id in (
            "INSTITUTION-A",
            "INSTITUTION-B",
            "INSTITUTION-C",
            "INSTITUTION-D",
        ):
            authority_dir = self.root / "institutions" / authority_id
            fed.authority_init(authority_id, authority_dir)
            self.authorities[authority_id] = authority_dir
            descriptors.append(authority_dir / fed.AUTHORITY_PUBLIC)

        initialized = huc.initialize(
            self.issuer,
            threshold=3,
            authority_public_files=descriptors,
        )
        self.anchor = initialized["trust_anchor_sha256"]

        # Each institution enrolls independently using public-only material.
        for authority_id, authority_dir in self.authorities.items():
            package = self.root / f"enrollment-{authority_id}.zip"
            fed.export_enrollment(self.issuer, authority_id, package, self.anchor)
            fed.authority_enroll(authority_dir, package, self.anchor)

        self.requests = self.root / "holder-requests"
        self.output = self.root / "issued-credentials"

    def tearDown(self):
        self.tmp.cleanup()

    def make_csr(self, common_name):
        result = huc.generate_request(self.requests, common_name)
        return Path(result["csr_file"])

    def approve(self, proposal, authority_ids):
        approvals = []
        for authority_id in authority_ids:
            output = self.root / f"{proposal.stem}-{authority_id}.approval.json"
            fed.authority_approve(
                self.authorities[authority_id], proposal, output
            )
            approvals.append(output)
        return approvals

    def sync_all_institutions(self):
        package = self.root / "institutional-state-sync.zip"
        fed.export_state(self.issuer, package, self.anchor)
        for authority_dir in self.authorities.values():
            fed.authority_sync(authority_dir, package)

    def test_four_institution_issue_renew_revoke_and_sync(self):
        # The issuer must never receive any institution's private signing key.
        for authority_id in self.authorities:
            self.assertFalse(
                (self.issuer / huc.AUTH_DIR / f"{authority_id}-private.pem").exists()
            )

        issue = self.root / "issue.proposal.json"
        fed.prepare_issue(self.issuer, self.make_csr("HUC Institutional Pilot"), issue)
        issued = fed.finalize_proposal(
            self.issuer,
            issue,
            self.approve(issue, ["INSTITUTION-A", "INSTITUTION-B", "INSTITUTION-C"]),
            self.output,
            self.anchor,
        )
        self.assertEqual(issued["quorum"], "3/4")
        self.assertFalse(issued["private_keys_transferred"])
        self.sync_all_institutions()

        old_certificate = Path(issued["certificate_file"])
        renewal = self.root / "renew.proposal.json"
        fed.prepare_renew(
            self.issuer, old_certificate, self.make_csr("HUC Institutional Pilot"),
            renewal, days=90,
        )
        renewed = fed.finalize_proposal(
            self.issuer,
            renewal,
            self.approve(renewal, ["INSTITUTION-B", "INSTITUTION-C", "INSTITUTION-D"]),
            self.output,
            self.anchor,
        )
        self.assertEqual(renewed["quorum"], "3/4")
        self.sync_all_institutions()

        old_status = huc.verify_certificate(
            self.issuer, old_certificate, expected_anchor_sha256=self.anchor
        )
        new_status = huc.verify_certificate(
            self.issuer, Path(renewed["certificate_file"]),
            expected_anchor_sha256=self.anchor,
        )
        self.assertEqual(old_status["utxo_status"], "SUPERSEDED")
        self.assertTrue(new_status["hybrid_valid"])

        revoke = self.root / "revoke.proposal.json"
        fed.prepare_revoke(
            self.issuer, Path(renewed["certificate_file"]),
            "institutional-pilot-revocation-test", revoke,
        )
        revoked = fed.finalize_proposal(
            self.issuer,
            revoke,
            self.approve(revoke, ["INSTITUTION-A", "INSTITUTION-C", "INSTITUTION-D"]),
            self.output,
            self.anchor,
        )
        self.assertEqual(revoked["status"], "REVOKED")
        self.sync_all_institutions()

        final_status = huc.verify_certificate(
            self.issuer, Path(renewed["certificate_file"]),
            expected_anchor_sha256=self.anchor,
        )
        self.assertEqual(final_status["utxo_status"], "REVOKED")
        self.assertFalse(final_status["hybrid_valid"])

    def test_four_institution_quorum_rejects_two_approvals(self):
        proposal = self.root / "insufficient-quorum.proposal.json"
        fed.prepare_issue(
            self.issuer, self.make_csr("HUC Quorum Negative Test"), proposal
        )
        approvals = self.approve(
            proposal, ["INSTITUTION-A", "INSTITUTION-B"]
        )
        with self.assertRaisesRegex(ValueError, "Quórum insuficiente"):
            fed.finalize_proposal(
                self.issuer, proposal, approvals, self.output, self.anchor
            )
        self.assertEqual(huc.audit(self.issuer, self.anchor)["event_count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
