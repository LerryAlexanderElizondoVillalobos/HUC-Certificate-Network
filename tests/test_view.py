import json
import tempfile
import unittest
from pathlib import Path

import huc
import huc_replicated as rsp
import huc_view as view


class ViewChangeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.nodes = {}
        public = []
        for name in ("VIEW-A", "VIEW-B", "VIEW-C", "VIEW-D"):
            d = self.root / name
            rsp.node_init(name, d)
            self.nodes[name] = d
            public.append(d / rsp.NODE_PUBLIC)
        self.network_path = self.root / "network.json"
        result = rsp.create_network(public, self.network_path, 1)
        self.pin = result["network_sha256"]
        for node in self.nodes.values():
            rsp.node_join(node, self.network_path, self.pin)
            view.initialize_view_state(node)
        self.proposals = self.root / "proposals"
        self.votes = self.root / "votes"
        self.commits = self.root / "commits"
        self.proposals.mkdir(); self.votes.mkdir(); self.commits.mkdir()
        self.cert1 = "1" * 64
        self.cc1 = "a" * 64
        self.cert2 = "2" * 64
        self.cc2 = "b" * 64

    def tearDown(self):
        self.tmp.cleanup()

    def make_proposal(self, proposer="VIEW-A", cert=None, cc=None, name="proposal"):
        raw = self.proposals / f"{name}-raw.json"
        annotated = self.proposals / f"{name}.json"
        rsp.create_proposal(self.nodes[proposer], "ISSUE", cert or self.cert1, cc or self.cc1, raw)
        view.annotate_proposal_for_view(self.nodes[proposer], raw, annotated)
        return annotated

    def make_votes(self, proposal_path, names, prefix):
        proposal = rsp._read(proposal_path)
        paths = []
        for name in names:
            view.validate_proposal_view(self.nodes[name], proposal)
            view.remember_proposal(self.nodes[name], proposal)
            path = self.votes / f"{prefix}-{name}.json"
            rsp.vote_proposal(self.nodes[name], proposal_path, path)
            paths.append(path)
        return paths

    def change_view(self, names=("VIEW-A", "VIEW-B", "VIEW-C"), target=1, name="view1"):
        messages = [view.create_view_change_message(self.nodes[n], target) for n in names]
        cert_path = self.commits / f"{name}.json"
        view.assemble_view_certificate(self.nodes[names[0]], messages, cert_path)
        for node in self.nodes.values():
            view.install_view_certificate(node, cert_path)
        return cert_path

    def test_view_change_rotates_primary_with_quorum(self):
        self.change_view()
        for node in self.nodes.values():
            state = view.load_view_state(node)
            self.assertEqual(state["view"], 1)
        network = rsp.load_network(self.nodes["VIEW-A"])
        self.assertEqual(view.primary_for_view(network, 1), "VIEW-B")

    def test_insufficient_view_change_quorum_rejected(self):
        messages = [view.create_view_change_message(self.nodes[n], 1) for n in ("VIEW-A", "VIEW-B")]
        with self.assertRaisesRegex(ValueError, "Quórum insuficiente"):
            view.assemble_view_certificate(self.nodes["VIEW-A"], messages, self.commits / "bad.json")

    def test_conflicting_slot_locks_stop_view_change(self):
        p1 = self.make_proposal("VIEW-A", self.cert1, self.cc1, "conflict-a")
        p2 = self.make_proposal("VIEW-A", self.cert2, self.cc2, "conflict-b")
        self.make_votes(p1, ["VIEW-A"], "lock-a")
        self.make_votes(p2, ["VIEW-B"], "lock-b")
        messages = [view.create_view_change_message(self.nodes[n], 1) for n in ("VIEW-A", "VIEW-B", "VIEW-C")]
        with self.assertRaisesRegex(ValueError, "Conflicto de propuestas bloqueadas"):
            view.assemble_view_certificate(self.nodes["VIEW-A"], messages, self.commits / "conflict-view.json")

    def test_view_change_carries_single_locked_proposal_forward(self):
        proposal_path = self.make_proposal(name="recovery")
        proposal = rsp._read(proposal_path)
        self.make_votes(proposal_path, ["VIEW-A", "VIEW-B", "VIEW-C"], "recovery")
        messages = [view.create_view_change_message(self.nodes[n], 1) for n in ("VIEW-A", "VIEW-B", "VIEW-C")]
        cert_path = self.commits / "recovery-view.json"
        view.assemble_view_certificate(self.nodes["VIEW-A"], messages, cert_path)
        for node in self.nodes.values():
            view.install_view_certificate(node, cert_path)
            self.assertEqual(view.load_view_state(node)["recovery_proposal_id"], proposal["proposal_id"])
        # The new view must preserve and finish the outstanding proposal.
        self.assertTrue(view.validate_proposal_view(self.nodes["VIEW-D"], proposal))
        d_vote = self.votes / "recovery-VIEW-D.json"
        rsp.vote_proposal(self.nodes["VIEW-D"], proposal_path, d_vote)
        commit = self.commits / "recovery-commit.json"
        rsp.assemble_commit(self.nodes["VIEW-D"], proposal_path,
                            [self.votes / f"recovery-{n}.json" for n in ("VIEW-A", "VIEW-B", "VIEW-C")] + [d_vote], commit)
        for name, node in self.nodes.items():
            rsp.apply_commit(node, commit)
            view.clear_recovery_after_commit(node, rsp._read(commit))
            self.assertIsNone(view.load_view_state(node)["recovery_proposal_id"])

    def test_new_view_primary_can_propose_when_no_slot_is_locked(self):
        self.change_view()
        raw = self.proposals / "view2-raw.json"
        annotated = self.proposals / "view2.json"
        rsp.create_proposal(self.nodes["VIEW-B"], "ISSUE", self.cert1, self.cc1, raw)
        view.annotate_proposal_for_view(self.nodes["VIEW-B"], raw, annotated)
        for node in self.nodes.values():
            self.assertTrue(view.validate_proposal_view(node, rsp._read(annotated)))

    def test_non_primary_cannot_annotate_normal_proposal(self):
        raw = self.proposals / "non-primary-raw.json"
        rsp.create_proposal(self.nodes["VIEW-B"], "ISSUE", self.cert1, self.cc1, raw)
        with self.assertRaisesRegex(ValueError, "Solo el proponente"):
            view.annotate_proposal_for_view(self.nodes["VIEW-B"], raw, self.proposals / "non-primary.json")


if __name__ == "__main__":
    unittest.main(verbosity=2)
