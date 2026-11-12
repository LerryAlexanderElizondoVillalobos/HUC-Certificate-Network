import json
import tempfile
import unittest
import zipfile
from pathlib import Path

import huc
import huc_bft as bft
import huc_replicated as rsp


class BFTStateSyncTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.nodes = {}
        public = []
        for name in ("SYNC-A", "SYNC-B", "SYNC-C", "SYNC-D"):
            node = self.root / name
            rsp.node_init(name, node)
            self.nodes[name] = node
            public.append(node / rsp.NODE_PUBLIC)
        self.network_path = self.root / "network.json"
        info = rsp.create_network(public, self.network_path, fault_tolerance=1)
        for node in self.nodes.values():
            rsp.node_join(node, self.network_path, info["network_sha256"])
            bft.initialize_node(node)

    def tearDown(self):
        self.tmp.cleanup()

    def commit_issue(self):
        node = self.nodes["SYNC-A"]
        proposal_path = self.root / "proposal.json"
        bft.create_operation_proposal(node, "ISSUE", huc.sha256(b"sync-cert"),
                                      huc.sha256(b"sync-cc"), proposal_path)
        pp_path = self.root / "pp.json"
        bft.create_preprepare(node, proposal_path, pp_path)
        pp = rsp._read(pp_path)
        network = rsp.load_network(node)
        prep_votes = [bft.accept_preprepare(self.nodes[x], pp)
                      for x in ("SYNC-A", "SYNC-B", "SYNC-C")]
        prep = bft.assemble_prepare_certificate(network, bft.load_state(node), pp, prep_votes)
        acks = [bft.create_prepared_ack(self.nodes[x], prep)
                for x in ("SYNC-A", "SYNC-B", "SYNC-C")]
        prepared = bft.assemble_prepared_certificate(network, bft.load_state(node), prep, acks)
        for replica in self.nodes.values():
            bft.accept_prepared_certificate(replica, prepared)
        commits = [bft.create_commit_vote(self.nodes[x], prepared)
                   for x in ("SYNC-A", "SYNC-B", "SYNC-C")]
        cert = bft.assemble_commit_certificate(network, bft.load_state(node), prepared, commits)
        for replica in self.nodes.values():
            bft.apply_commit_certificate(replica, cert)
        return cert

    def test_export_and_sync_rebuilds_verified_state(self):
        self.commit_issue()
        package = self.root / "state.zip"
        result = bft.export_state(self.nodes["SYNC-A"], package)
        self.assertFalse(result["private_keys_included"])
        synced = bft.sync_state(self.nodes["SYNC-D"], package)
        self.assertEqual(synced["result"], "bft_state_synchronized")
        self.assertEqual(synced["sequence"], 1)
        self.assertEqual(bft.status(self.nodes["SYNC-D"])["head_hash"],
                         bft.status(self.nodes["SYNC-A"])["head_hash"])
        with zipfile.ZipFile(package) as archive:
            names = archive.namelist()
        self.assertNotIn(rsp.NODE_PRIVATE, names)
        self.assertNotIn("bft-locks.json", names)

    def test_rollback_package_is_rejected(self):
        genesis_package = self.root / "genesis.zip"
        bft.export_state(self.nodes["SYNC-D"], genesis_package)
        self.commit_issue()
        with self.assertRaisesRegex(ValueError, "rollback de historial"):
            bft.sync_state(self.nodes["SYNC-D"], genesis_package)

    def test_tampered_commit_package_is_rejected(self):
        self.commit_issue()
        original = self.root / "original.zip"
        bft.export_state(self.nodes["SYNC-A"], original)
        tampered = self.root / "tampered.zip"
        with zipfile.ZipFile(original) as src, zipfile.ZipFile(tampered, "w", zipfile.ZIP_DEFLATED) as dst:
            for item in src.infolist():
                data = src.read(item.filename)
                if item.filename == bft.LEDGER_FILE:
                    ledger = json.loads(data.decode().splitlines()[0])
                    ledger["body"]["commit_id"] = "0" * 64
                    data = (json.dumps(ledger) + "\n").encode()
                dst.writestr(item.filename, data)
        with self.assertRaises(ValueError):
            bft.sync_state(self.nodes["SYNC-D"], tampered)


if __name__ == "__main__":
    unittest.main(verbosity=2)
