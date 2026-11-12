import json
import tempfile
import unittest
import zipfile
from pathlib import Path

import huc
import huc_federation as fed


class IndependentAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.workspace = self.root / "coordinator-workspace"
        self.authorities = {}
        descriptors = []
        for aid in ["INSTITUTION-A", "INSTITUTION-B", "INSTITUTION-C"]:
            authority_dir = self.root / "devices" / aid
            fed.authority_init(aid, authority_dir)
            self.authorities[aid] = authority_dir
            descriptors.append(authority_dir / fed.AUTHORITY_PUBLIC)
        init = huc.initialize(self.workspace, threshold=2, authority_public_files=descriptors)
        self.pin = init["trust_anchor_sha256"]
        self.policy = huc.load_policy(self.workspace)
        self.assertTrue(init["external_authorities"])
        for aid, authority_dir in self.authorities.items():
            enroll_package = self.root / f"{aid}-enrollment.zip"
            fed.export_enrollment(self.workspace, aid, enroll_package, self.pin)
            fed.authority_enroll(authority_dir, enroll_package, self.pin)
        self.requests = self.root / "holder-requests"
        self.output = self.root / "finalized"

    def tearDown(self):
        self.tmp.cleanup()

    def csr(self, name="LAEV Independent Authority Test"):
        result = huc.generate_request(self.requests, name)
        return Path(result["csr_file"])

    def approvals(self, proposal_path, authority_ids):
        paths = []
        for aid in authority_ids:
            approval_path = self.root / f"{proposal_path.stem}-{aid}.approval.json"
            fed.authority_approve(self.authorities[aid], proposal_path, approval_path)
            paths.append(approval_path)
        return paths

    def sync_all(self):
        package = self.root / "state-sync.zip"
        fed.export_state(self.workspace, package, self.pin)
        for authority_dir in self.authorities.values():
            fed.authority_sync(authority_dir, package)

    def test_independent_authority_issue_and_verify(self):
        # Coordinator stores only public authority descriptors, not signer keys.
        for aid in self.authorities:
            self.assertFalse((self.workspace / huc.AUTH_DIR / f"{aid}-private.pem").exists())
        self.assertFalse(any((self.workspace / huc.AUTH_DIR).glob("*-private.pem")))

        proposal = self.root / "issue.proposal.json"
        fed.prepare_issue(self.workspace, self.csr(), proposal, days=90)
        approvals = self.approvals(proposal, ["INSTITUTION-A", "INSTITUTION-C"])
        result = fed.finalize_proposal(self.workspace, proposal, approvals, self.output, self.pin)
        self.assertEqual(result["quorum"], "2/3")
        self.assertFalse(result["private_keys_transferred"])
        verified = huc.verify_certificate(self.workspace, Path(result["certificate_file"]),
                                          expected_anchor_sha256=self.pin)
        self.assertTrue(verified["hybrid_valid"])
        self.assertEqual(set(verified["consensus_signers"]), {"INSTITUTION-A", "INSTITUTION-C"})

    def test_full_lifecycle_renew_revoke_with_sync(self):
        proposal = self.root / "issue.proposal.json"
        fed.prepare_issue(self.workspace, self.csr(), proposal, days=90)
        issued = fed.finalize_proposal(
            self.workspace, proposal,
            self.approvals(proposal, ["INSTITUTION-A", "INSTITUTION-B"]), self.output, self.pin
        )
        self.sync_all()

        renew_proposal = self.root / "renew.proposal.json"
        fed.prepare_renew(self.workspace, Path(issued["certificate_file"]),
                          self.csr(), renew_proposal, days=90)
        renewed = fed.finalize_proposal(
            self.workspace, renew_proposal,
            self.approvals(renew_proposal, ["INSTITUTION-B", "INSTITUTION-C"]), self.output, self.pin
        )
        old_check = huc.verify_certificate(self.workspace, Path(issued["certificate_file"]),
                                           expected_anchor_sha256=self.pin)
        new_check = huc.verify_certificate(self.workspace, Path(renewed["certificate_file"]),
                                           expected_anchor_sha256=self.pin)
        self.assertEqual(old_check["utxo_status"], "SUPERSEDED")
        self.assertFalse(old_check["hybrid_valid"])
        self.assertTrue(new_check["hybrid_valid"])
        self.sync_all()

        revoke_proposal = self.root / "revoke.proposal.json"
        fed.prepare_revoke(self.workspace, Path(renewed["certificate_file"]),
                           "key-compromise", revoke_proposal)
        revoked = fed.finalize_proposal(
            self.workspace, revoke_proposal,
            self.approvals(revoke_proposal, ["INSTITUTION-A", "INSTITUTION-C"]), self.output, self.pin
        )
        self.assertEqual(revoked["status"], "REVOKED")
        final_check = huc.verify_certificate(self.workspace, Path(renewed["certificate_file"]),
                                             expected_anchor_sha256=self.pin)
        self.assertEqual(final_check["utxo_status"], "REVOKED")
        self.assertFalse(final_check["hybrid_valid"])

    def test_quorum_is_enforced_at_finalize(self):
        proposal = self.root / "issue.proposal.json"
        fed.prepare_issue(self.workspace, self.csr(), proposal)
        approvals = self.approvals(proposal, ["INSTITUTION-A"])
        with self.assertRaisesRegex(ValueError, "Quórum insuficiente"):
            fed.finalize_proposal(self.workspace, proposal, approvals, self.output, self.pin)
        self.assertEqual(huc.audit(self.workspace, self.pin)["event_count"], 0)

    def test_stale_proposal_and_checkpoint_equivocation_are_rejected(self):
        first = self.root / "first.proposal.json"
        second = self.root / "second.proposal.json"
        fed.prepare_issue(self.workspace, self.csr("Person One"), first)
        fed.prepare_issue(self.workspace, self.csr("Person Two"), second)
        first_result = fed.finalize_proposal(
            self.workspace, first, self.approvals(first, ["INSTITUTION-A", "INSTITUTION-B"]), self.output, self.pin
        )
        self.assertTrue(Path(first_result["certificate_file"]).exists())
        # Signers A/B are locked to the first proposal at that checkpoint.
        with self.assertRaisesRegex(ValueError, "Anti-equivocación"):
            fed.authority_approve(self.authorities["INSTITUTION-B"], second,
                                  self.root / "second-B.approval.json")
        # Authority C can sign, but cannot form a 2-of-3 quorum alone.
        c_approval = self.root / "second-C.approval.json"
        fed.authority_approve(self.authorities["INSTITUTION-C"], second, c_approval)
        with self.assertRaisesRegex(ValueError, "Quórum insuficiente"):
            fed.finalize_proposal(self.workspace, second, [c_approval], self.output, self.pin)
        # After state sync, the old proposal is stale at the authority as well.
        self.sync_all()
        with self.assertRaisesRegex(ValueError, "Propuesta obsoleta"):
            fed.authority_approve(self.authorities["INSTITUTION-C"], second,
                                  self.root / "second-C-after-sync.approval.json")

    def test_authority_refuses_stale_local_ledger(self):
        proposal = self.root / "issue.proposal.json"
        fed.prepare_issue(self.workspace, self.csr(), proposal)
        # One authority has not received a new state package if the coordinator advances.
        fed.finalize_proposal(
            self.workspace, proposal,
            self.approvals(proposal, ["INSTITUTION-A", "INSTITUTION-B"]), self.output, self.pin
        )
        next_proposal = self.root / "next.proposal.json"
        fed.prepare_issue(self.workspace, self.csr("Another Person"), next_proposal)
        approval_file = self.root / "stale-approval.json"
        with self.assertRaisesRegex(ValueError, "Propuesta obsoleta"):
            fed.authority_approve(self.authorities["INSTITUTION-C"], next_proposal, approval_file)

    def test_authority_will_not_double_sign_same_checkpoint(self):
        first = self.root / "first.proposal.json"
        second = self.root / "second.proposal.json"
        fed.prepare_issue(self.workspace, self.csr("First Applicant"), first)
        fed.prepare_issue(self.workspace, self.csr("Second Applicant"), second)
        fed.authority_approve(self.authorities["INSTITUTION-A"], first,
                              self.root / "first-A.approval.json")
        with self.assertRaisesRegex(ValueError, "Anti-equivocación"):
            fed.authority_approve(self.authorities["INSTITUTION-A"], second,
                                  self.root / "second-A.approval.json")

    def test_concurrent_approval_requests_cannot_double_sign_checkpoint(self):
        from concurrent.futures import ThreadPoolExecutor
        first = self.root / "concurrent-first.json"
        second = self.root / "concurrent-second.json"
        fed.prepare_issue(self.workspace, self.csr("Concurrent One"), first)
        fed.prepare_issue(self.workspace, self.csr("Concurrent Two"), second)

        def attempt(args):
            proposal_path, output_path = args
            try:
                fed.authority_approve(self.authorities["INSTITUTION-A"], proposal_path, output_path)
                return "signed"
            except ValueError as exc:
                if "Anti-equivocación" in str(exc):
                    return "blocked"
                raise

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, [
                (first, self.root / "concurrent-A1.json"),
                (second, self.root / "concurrent-A2.json"),
            ]))
        self.assertEqual(results.count("signed"), 1)
        self.assertEqual(results.count("blocked"), 1)

    def test_sync_rejects_ledger_rollback(self):
        old_package = self.root / "old-state.zip"
        fed.export_state(self.workspace, old_package, self.pin)
        proposal = self.root / "issue.proposal.json"
        fed.prepare_issue(self.workspace, self.csr(), proposal)
        fed.finalize_proposal(self.workspace, proposal,
                              self.approvals(proposal, ["INSTITUTION-A", "INSTITUTION-B"]), self.output, self.pin)
        new_package = self.root / "new-state.zip"
        fed.export_state(self.workspace, new_package, self.pin)
        authority_dir = self.authorities["INSTITUTION-A"]
        fed.authority_sync(authority_dir, new_package)
        with self.assertRaisesRegex(ValueError, "rollback o bifurcación"):
            fed.authority_sync(authority_dir, old_package)

    def test_same_public_key_cannot_be_registered_under_two_authority_ids(self):
        duplicate_workspace = self.root / "duplicate-workspace"
        descriptor_a = self.authorities["INSTITUTION-A"] / fed.AUTHORITY_PUBLIC
        descriptor = json.loads(descriptor_a.read_text())
        duplicate = dict(descriptor)
        duplicate["authority_id"] = "INSTITUTION-A-ALIAS"
        duplicate_path = self.root / "duplicate-public.json"
        duplicate_path.write_text(json.dumps(duplicate))
        with self.assertRaisesRegex(ValueError, "clave pública independiente"):
            huc.initialize(duplicate_workspace, threshold=2,
                           authority_public_files=[descriptor_a, duplicate_path,
                               self.authorities["INSTITUTION-B"] / fed.AUTHORITY_PUBLIC])

    def test_enrollment_and_sync_packages_have_no_private_keys(self):
        package = self.root / "check-enrollment.zip"
        fed.export_enrollment(self.workspace, "INSTITUTION-A", package, self.pin)
        with zipfile.ZipFile(package) as zf:
            names = zf.namelist()
        self.assertFalse(any("private" in x.lower() or x.endswith(".key") for x in names))

    def test_altered_approval_is_rejected(self):
        proposal = self.root / "issue.proposal.json"
        fed.prepare_issue(self.workspace, self.csr(), proposal)
        approval_paths = self.approvals(proposal, ["INSTITUTION-A", "INSTITUTION-B"])
        approval = json.loads(approval_paths[0].read_text())
        approval["proposal_id"] = "0" * 64
        approval_paths[0].write_text(json.dumps(approval))
        with self.assertRaisesRegex(ValueError, "otra propuesta"):
            fed.finalize_proposal(self.workspace, proposal, approval_paths, self.output, self.pin)


if __name__ == "__main__":
    unittest.main(verbosity=2)
