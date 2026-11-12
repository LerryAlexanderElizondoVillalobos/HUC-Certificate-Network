import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from pathlib import Path

import huc
import huc_bft as bft
import huc_replicated as rsp


class HUCExampleBFTTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.nodes = {}
        public = []
        for name in ("NODE-A", "NODE-B", "NODE-C", "NODE-D"):
            d = self.root / name.lower()
            rsp.node_init(name, d)
            self.nodes[name] = d
            public.append(d / rsp.NODE_PUBLIC)
        self.network_path = self.root / "network.json"
        info = rsp.create_network(public, self.network_path, fault_tolerance=1)
        self.network_pin = info["network_sha256"]
        for d in self.nodes.values():
            rsp.node_join(d, self.network_path, self.network_pin)
            bft.initialize_node(d)
        self.net = rsp.validate_network(rsp._read(self.network_path))
        self.proposals = self.root / "proposals"
        self.proposals.mkdir()
        self.hash1 = huc.sha256(b"bft-x509-1")
        self.hash2 = huc.sha256(b"bft-x509-2")
        self.cc1 = huc.sha256(b"bft-huc-cc-1")
        self.cc2 = huc.sha256(b"bft-huc-cc-2")

    def tearDown(self):
        self.tmp.cleanup()

    def propose(self, action="ISSUE", cert=None, cc=None, previous=None):
        path = self.proposals / f"{action.lower()}-{len(list(self.proposals.iterdir()))}.json"
        bft.create_operation_proposal(
            self.nodes["NODE-A"], action, cert or self.hash1, cc or self.cc1,
            path, previous_certificate_sha256=previous,
            metadata={"reason": "test-revoke"} if action == "REVOKE" else {},
        )
        return path

    def preprepare(self, proposal_path):
        path = self.root / "preprepare.json"
        bft.create_preprepare(self.nodes["NODE-A"], proposal_path, path)
        return rsp._read(path)

    def prepare_certificate(self, proposal_path, validators=("NODE-A", "NODE-B", "NODE-C", "NODE-D")):
        pp = self.preprepare(proposal_path)
        votes = [bft.accept_preprepare(self.nodes[v], pp) for v in validators]
        return pp, bft.assemble_prepare_certificate(self.net, bft.load_state(self.nodes["NODE-A"]), pp, votes)

    def prepared_certificate(self, pp, prepare_cert, validators=("NODE-A", "NODE-B", "NODE-C", "NODE-D")):
        acks = [bft.create_prepared_ack(self.nodes[v], prepare_cert) for v in validators]
        pc = bft.assemble_prepared_certificate(self.net, bft.load_state(self.nodes["NODE-A"]), prepare_cert, acks)
        for node in self.nodes.values():
            bft.accept_prepared_certificate(node, pc)
        return pc

    def commit(self, pc, validators=("NODE-A", "NODE-B", "NODE-C", "NODE-D")):
        votes = [bft.create_commit_vote(self.nodes[v], pc) for v in validators]
        cert = bft.assemble_commit_certificate(self.net, bft.load_state(self.nodes["NODE-A"]), pc, votes)
        for node in self.nodes.values():
            bft.apply_commit_certificate(node, cert)
        return cert

    def test_full_preprepare_prepare_prepared_commit_flow(self):
        proposal = self.propose()
        _, prepare_cert = self.prepare_certificate(proposal)
        pc = self.prepared_certificate(self.preprepare(proposal), prepare_cert)
        commit = self.commit(pc)
        states = [bft.load_state(node) for node in self.nodes.values()]
        self.assertEqual({s["sequence"] for s in states}, {1})
        self.assertEqual({s["head_hash"] for s in states}, {commit["body"]["commit_id"]})

    def test_one_offline_replica_still_reaches_three_of_four_quorum(self):
        proposal = self.propose()
        pp = self.preprepare(proposal)
        prep_votes = [bft.accept_preprepare(self.nodes[x], pp) for x in ("NODE-A", "NODE-B", "NODE-C")]
        prepare_cert = bft.assemble_prepare_certificate(self.net, bft.load_state(self.nodes["NODE-A"]), pp, prep_votes)
        acks = [bft.create_prepared_ack(self.nodes[x], prepare_cert) for x in ("NODE-A", "NODE-B", "NODE-C")]
        pc = bft.assemble_prepared_certificate(self.net, bft.load_state(self.nodes["NODE-A"]), prepare_cert, acks)
        for x in ("NODE-A", "NODE-B", "NODE-C"):
            bft.accept_prepared_certificate(self.nodes[x], pc)
        commits = [bft.create_commit_vote(self.nodes[x], pc) for x in ("NODE-A", "NODE-B", "NODE-C")]
        cert = bft.assemble_commit_certificate(self.net, bft.load_state(self.nodes["NODE-A"]), pc, commits)
        for x in ("NODE-A", "NODE-B", "NODE-C"):
            bft.apply_commit_certificate(self.nodes[x], cert)
        self.assertEqual(bft.load_state(self.nodes["NODE-C"])["sequence"], 1)
        self.assertEqual(bft.load_state(self.nodes["NODE-D"])["sequence"], 0)

    def test_prepare_quorum_minus_one_rejected(self):
        proposal = self.propose()
        pp = self.preprepare(proposal)
        votes = [bft.accept_preprepare(self.nodes[x], pp) for x in ("NODE-A", "NODE-B")]
        with self.assertRaisesRegex(ValueError, "Quórum PREPARE insuficiente"):
            bft.assemble_prepare_certificate(self.net, bft.load_state(self.nodes["NODE-A"]), pp, votes)

    def test_prepared_lock_quorum_minus_one_rejected(self):
        proposal = self.propose()
        pp = self.preprepare(proposal)
        votes = [bft.accept_preprepare(self.nodes[x], pp) for x in ("NODE-A", "NODE-B", "NODE-C")]
        pc = bft.assemble_prepare_certificate(self.net, bft.load_state(self.nodes["NODE-A"]), pp, votes)
        acks = [bft.create_prepared_ack(self.nodes[x], pc) for x in ("NODE-A", "NODE-B")]
        with self.assertRaisesRegex(ValueError, "Quórum de prepared locks insuficiente"):
            bft.assemble_prepared_certificate(self.net, bft.load_state(self.nodes["NODE-A"]), pc, acks)

    def test_commit_quorum_minus_one_rejected(self):
        proposal = self.propose()
        pp, prepare_cert = self.prepare_certificate(proposal)
        pc = self.prepared_certificate(pp, prepare_cert)
        votes = [bft.create_commit_vote(self.nodes[x], pc) for x in ("NODE-A", "NODE-B")]
        with self.assertRaisesRegex(ValueError, "Quórum COMMIT insuficiente"):
            bft.assemble_commit_certificate(self.net, bft.load_state(self.nodes["NODE-A"]), pc, votes)

    def test_concurrent_conflicting_preprepares_cannot_double_sign(self):
        p1 = self.propose("ISSUE", self.hash1, self.cc1)
        p2 = self.propose("ISSUE", self.hash2, self.cc2)
        pp1 = self.preprepare(p1)
        pp2 = self.preprepare(p2)
        barrier = Barrier(2)

        def attempt(pp):
            barrier.wait(timeout=2)
            try:
                return ("accepted", bft.accept_preprepare(self.nodes["NODE-B"], pp))
            except ValueError as exc:
                return ("rejected", str(exc))

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, (pp1, pp2)))
        self.assertEqual([x[0] for x in results].count("accepted"), 1)
        self.assertEqual([x[0] for x in results].count("rejected"), 1)
        rejection = next(x[1] for x in results if x[0] == "rejected")
        self.assertIn("Equivocación", rejection)
        saved = bft._read(self.nodes["NODE-B"] / bft.LOCKS_FILE)
        self.assertEqual(len(saved["prepare"]), 1)

    def test_conflicting_preprepare_cannot_get_three_prepare_votes(self):
        p1 = self.propose("ISSUE", self.hash1, self.cc1)
        p2 = self.propose("ISSUE", self.hash2, self.cc2)
        pp1 = self.preprepare(p1)
        pp2 = json.loads(json.dumps(pp1))
        pp2["payload"]["proposal"] = rsp._read(p2)
        pp2["payload"]["proposal_id"] = rsp._read(p2)["proposal_id"]
        pp2["payload"]["request_hash"] = bft._hash(rsp._proposal_payload(rsp._read(p2)))
        pp2["preprepare_id"] = bft._hash(pp2["payload"])
        # A malicious primary cannot sign the altered body; even with a forged
        # body, replicas must reject it before PREPARE.
        for name in ("NODE-B", "NODE-C", "NODE-D"):
            with self.assertRaises(ValueError):
                bft.accept_preprepare(self.nodes[name], pp2)
        votes = [bft.accept_preprepare(self.nodes[x], pp1) for x in ("NODE-A", "NODE-B", "NODE-C")]
        self.assertEqual(len(votes), 3)

    def test_duplicate_prepare_signer_rejected(self):
        proposal = self.propose(); pp = self.preprepare(proposal)
        vote = bft.accept_preprepare(self.nodes["NODE-A"], pp)
        with self.assertRaisesRegex(ValueError, "duplicado"):
            bft.assemble_prepare_certificate(self.net, bft.load_state(self.nodes["NODE-A"]), pp, [vote, vote, vote])

    def test_tampered_prepare_signature_rejected(self):
        proposal = self.propose(); pp = self.preprepare(proposal)
        votes = [bft.accept_preprepare(self.nodes[x], pp) for x in ("NODE-A", "NODE-B", "NODE-C")]
        votes[0]["payload"]["request_hash"] = self.hash2
        with self.assertRaises(ValueError):
            bft.assemble_prepare_certificate(self.net, bft.load_state(self.nodes["NODE-A"]), pp, votes)

    def test_replay_commit_after_apply_is_idempotent_but_replay_for_next_slot_rejected(self):
        proposal = self.propose(); pp, prep = self.prepare_certificate(proposal); pc = self.prepared_certificate(pp, prep)
        cert = self.commit(pc)
        duplicate = bft.apply_commit_certificate(self.nodes["NODE-A"], cert)
        self.assertEqual(duplicate["result"], "already_committed")
        with self.assertRaises(ValueError):
            bft._verify_commit_certificate(self.net, bft.load_state(self.nodes["NODE-A"]), cert)

    def test_prepared_certificate_survives_view_change_and_is_reproposed(self):
        proposal = self.propose()
        pp = self.preprepare(proposal)
        prep_votes = [bft.accept_preprepare(self.nodes[x], pp) for x in ("NODE-A", "NODE-B", "NODE-C")]
        prep_cert = bft.assemble_prepare_certificate(self.net, bft.load_state(self.nodes["NODE-A"]), pp, prep_votes)
        # Three replicas durably lock the same prepared request; do not assemble
        # the aggregate PreparedCertificate before view change.
        [bft.create_prepared_ack(self.nodes[x], prep_cert) for x in ("NODE-A", "NODE-B", "NODE-C")]
        view_changes = [bft.create_view_change(self.nodes[x], 1) for x in ("NODE-A", "NODE-B", "NODE-C")]
        new_view_path = self.root / "new-view.json"
        bft.assemble_new_view(self.nodes["NODE-B"], view_changes, new_view_path)
        new_view = rsp._read(new_view_path)
        self.assertEqual(new_view["body"]["selected_prepared_certificate"]["body"]["request_hash"],
                         pp["payload"]["request_hash"])
        for node in self.nodes.values():
            bft.install_new_view(node, new_view)
        recovered_pp_path = self.root / "recovered-preprepare.json"
        bft.repropose_selected(self.nodes["NODE-B"], recovered_pp_path)
        recovered_pp = rsp._read(recovered_pp_path)
        self.assertEqual(recovered_pp["payload"]["request_hash"], pp["payload"]["request_hash"])
        new_prep_votes = [bft.accept_preprepare(self.nodes[x], recovered_pp) for x in ("NODE-A", "NODE-B", "NODE-C")]
        new_prep = bft.assemble_prepare_certificate(self.net, bft.load_state(self.nodes["NODE-A"]), recovered_pp, new_prep_votes)
        new_acks = [bft.create_prepared_ack(self.nodes[x], new_prep) for x in ("NODE-A", "NODE-B", "NODE-C")]
        new_pc = bft.assemble_prepared_certificate(self.net, bft.load_state(self.nodes["NODE-A"]), new_prep, new_acks)
        for node in self.nodes.values():
            bft.accept_prepared_certificate(node, new_pc)
        commit_votes = [bft.create_commit_vote(self.nodes[x], new_pc) for x in ("NODE-A", "NODE-B", "NODE-C")]
        commit_cert = bft.assemble_commit_certificate(self.net, bft.load_state(self.nodes["NODE-A"]), new_pc, commit_votes)
        for node in self.nodes.values():
            bft.apply_commit_certificate(node, commit_cert)
        self.assertEqual({bft.status(x)["sequence"] for x in self.nodes.values()}, {1})

    def test_no_quorum_prepared_lock_can_be_released_after_valid_new_view(self):
        proposal = self.propose(); pp = self.preprepare(proposal)
        prep_votes = [bft.accept_preprepare(self.nodes[x], pp) for x in ("NODE-A", "NODE-B", "NODE-C")]
        prep_cert = bft.assemble_prepare_certificate(self.net, bft.load_state(self.nodes["NODE-A"]), pp, prep_votes)
        bft.create_prepared_ack(self.nodes["NODE-A"], prep_cert)  # one tentative lock only
        vcs = [bft.create_view_change(self.nodes[x], 1) for x in ("NODE-B", "NODE-C", "NODE-D")]
        new_view_path = self.root / "empty-new-view.json"
        bft.assemble_new_view(self.nodes["NODE-B"], vcs, new_view_path)
        new_view = rsp._read(new_view_path)
        self.assertIsNone(new_view["body"]["selected_prepared_certificate"])
        bft.install_new_view(self.nodes["NODE-A"], new_view)
        self.assertEqual(bft._read(self.nodes["NODE-A"] / bft.LOCKS_FILE)["prepared"], {})

    def test_view_change_quorum_insufficient(self):
        vcs = [bft.create_view_change(self.nodes[x], 1) for x in ("NODE-A", "NODE-B")]
        with self.assertRaisesRegex(ValueError, "Quórum VIEW_CHANGE insuficiente"):
            bft.assemble_new_view(self.nodes["NODE-B"], vcs, self.root / "no.json")

    def test_view_change_tampering_rejected(self):
        vcs = [bft.create_view_change(self.nodes[x], 1) for x in ("NODE-A", "NODE-B", "NODE-C")]
        vcs[0]["payload"]["reason"] = "forged"
        with self.assertRaises(ValueError):
            bft.assemble_new_view(self.nodes["NODE-B"], vcs, self.root / "no.json")

    def test_wrong_new_view_primary_rejected(self):
        vcs = [bft.create_view_change(self.nodes[x], 1) for x in ("NODE-A", "NODE-B", "NODE-C")]
        out = self.root / "nv.json"
        bft.assemble_new_view(self.nodes["NODE-B"], vcs, out)
        cert = rsp._read(out)
        cert["body"]["primary_id"] = "NODE-C"
        cert["new_view_id"] = bft._hash(cert["body"])
        with self.assertRaises(ValueError):
            bft.install_new_view(self.nodes["NODE-A"], cert)

    def test_conflicting_highest_prepared_certificates_trigger_safety_halt(self):
        proposal = self.propose(); pp = self.preprepare(proposal)
        prep_votes = [bft.accept_preprepare(self.nodes[x], pp) for x in ("NODE-A", "NODE-B", "NODE-C")]
        prep_cert = bft.assemble_prepare_certificate(self.net, bft.load_state(self.nodes["NODE-A"]), pp, prep_votes)
        acks = [bft.create_prepared_ack(self.nodes[x], prep_cert) for x in ("NODE-A", "NODE-B", "NODE-C")]
        pc = bft.assemble_prepared_certificate(self.net, bft.load_state(self.nodes["NODE-A"]), prep_cert, acks)
        vcs = [bft.create_view_change(self.nodes[x], 1) for x in ("NODE-A", "NODE-B", "NODE-C")]
        # Alter a different VC's prepared proof without its signature.
        vcs[1]["payload"]["prepared_certificate"] = None
        with self.assertRaises(ValueError):
            bft.assemble_new_view(self.nodes["NODE-B"], vcs, self.root / "bad-new-view.json")

    def test_renew_and_revoke_lifecycle_replicates(self):
        p1 = self.propose("ISSUE", self.hash1, self.cc1)
        pp, prep = self.prepare_certificate(p1); pc = self.prepared_certificate(pp, prep); self.commit(pc)
        p2 = self.propose("RENEW", self.hash2, self.cc2, previous=self.hash1)
        pp, prep = self.prepare_certificate(p2); pc = self.prepared_certificate(pp, prep); self.commit(pc)
        p3 = self.propose("REVOKE", self.hash2, self.cc2)
        pp, prep = self.prepare_certificate(p3); pc = self.prepared_certificate(pp, prep); self.commit(pc)
        for node in self.nodes.values():
            state = bft.load_state(node)
            self.assertEqual(state["certificates"][self.hash1]["status"], "SUPERSEDED")
            self.assertEqual(state["certificates"][self.hash2]["status"], "REVOKED")
            self.assertEqual(state["sequence"], 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
