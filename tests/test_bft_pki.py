import asyncio
import socket
import tempfile
import unittest
from pathlib import Path

import huc
import huc_bft as bft
import huc_bft_peer as bft_peer
import huc_peer as peer
import huc_replicated as rsp


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class BFTPKIEvidenceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.huc_workspace = self.root / "huc-ca"
        huc.initialize(self.huc_workspace, threshold=2, authority_count=3)
        csr_info = huc.generate_request(self.root / "requests", "HUC BFT P2P Test")
        issued = huc.issue_csr(self.huc_workspace, Path(csr_info["csr_file"]), days=30)
        self.certificate_path = Path(issued["certificate_file"])
        self.cc_path = Path(issued["consensus_certificate_file"])
        self.cert_hash = issued["certificate_sha256_der"]
        cc = huc.read_json(self.cc_path)
        self.cc_hash = huc.sha256(huc.canonical_json(cc))

        self.nodes = {}
        public = []
        for name in ("PKI-A", "PKI-B", "PKI-C", "PKI-D"):
            node = self.root / name
            rsp.node_init(name, node)
            self.nodes[name] = node
            public.append(node / rsp.NODE_PUBLIC)
        self.network_path = self.root / "network.json"
        network_info = rsp.create_network(
            public, self.network_path, fault_tolerance=1,
            ca_certificate_path=self.huc_workspace / huc.CA_CERT,
            consensus_policy_path=self.huc_workspace / huc.POLICY_FILE,
        )
        for node in self.nodes.values():
            rsp.node_join(node, self.network_path, network_info["network_sha256"])
            bft.initialize_node(node)
        self.ports = {name: free_port() for name in self.nodes}
        endpoints = [f"{name}=127.0.0.1:{port}" for name, port in self.ports.items()]
        peer_map_path = self.root / "peer-map.json"
        peer_info = peer.create_peer_map(self.network_path, network_info["network_sha256"],
                                         endpoints, peer_map_path)
        for node in self.nodes.values():
            peer.install_peer_map(node, peer_map_path, peer_info["peer_map_sha256"])
        self.servers = {}
        for name, node in self.nodes.items():
            server = peer.PeerServer(node, "127.0.0.1", self.ports[name])
            await server.start()
            self.servers[name] = server

    async def asyncTearDown(self):
        for server in self.servers.values():
            await server.close()
        self.tmp.cleanup()

    async def test_every_validator_checks_x509_and_huc_cc_before_bft_commit(self):
        proposal_path = self.root / "proposal.json"
        bft.create_operation_proposal(
            self.nodes["PKI-A"], "ISSUE", self.cert_hash, self.cc_hash, proposal_path,
            certificate_path=self.certificate_path,
            consensus_certificate_path=self.cc_path,
        )
        result = await bft_peer.broadcast_consensus(
            self.nodes["PKI-A"], proposal_path, self.root / "commit.json", timeout=1.0
        )
        self.assertEqual(result["result"], "bft_commit_replicated")
        states = [bft.load_state(n) for n in self.nodes.values()]
        self.assertEqual({s["sequence"] for s in states}, {1})
        self.assertEqual({s["certificates"][self.cert_hash]["status"] for s in states}, {"ACTIVE"})

    async def test_tampered_huc_cc_cannot_be_preprepared(self):
        proposal_path = self.root / "proposal.json"
        bft.create_operation_proposal(
            self.nodes["PKI-A"], "ISSUE", self.cert_hash, self.cc_hash, proposal_path,
            certificate_path=self.certificate_path,
            consensus_certificate_path=self.cc_path,
        )
        proposal = huc.read_json(proposal_path)
        proposal["payload"]["evidence"]["consensus_certificate"]["payload"]["authorized_state_at_issuance"] = "REVOKED"
        proposal["payload"]["consensus_certificate_sha256"] = huc.sha256(
            huc.canonical_json(proposal["payload"]["evidence"]["consensus_certificate"])
        )
        proposal["proposal_id"] = bft._hash(proposal["payload"])
        bad_path = self.root / "bad-proposal.json"
        huc.write_json(bad_path, proposal)
        with self.assertRaisesRegex(ValueError, "HUC-CC no certifica estado inicial ACTIVE"):
            bft.create_preprepare(self.nodes["PKI-A"], bad_path, self.root / "bad-pp.json")


if __name__ == "__main__":
    unittest.main(verbosity=2)
