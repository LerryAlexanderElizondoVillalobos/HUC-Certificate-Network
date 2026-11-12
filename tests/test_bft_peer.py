import asyncio
import socket
import sys
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


class BFTPeerNetworkTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.nodes = {}
        public = []
        for name in ("BFT-A", "BFT-B", "BFT-C", "BFT-D"):
            node = self.root / name
            rsp.node_init(name, node)
            self.nodes[name] = node
            public.append(node / rsp.NODE_PUBLIC)
        self.network_path = self.root / "network.json"
        network_info = rsp.create_network(public, self.network_path, fault_tolerance=1)
        self.network_pin = network_info["network_sha256"]
        for node in self.nodes.values():
            rsp.node_join(node, self.network_path, self.network_pin)
            bft.initialize_node(node)
        self.ports = {name: free_port() for name in self.nodes}
        endpoints = [f"{name}=127.0.0.1:{port}" for name, port in self.ports.items()]
        self.peer_map_path = self.root / "peer-map.json"
        peer_info = peer.create_peer_map(self.network_path, self.network_pin, endpoints, self.peer_map_path)
        self.peer_map_pin = peer_info["peer_map_sha256"]
        for node in self.nodes.values():
            peer.install_peer_map(node, self.peer_map_path, self.peer_map_pin)
        self.servers = {}
        for name, node in self.nodes.items():
            server = peer.PeerServer(node, "127.0.0.1", self.ports[name])
            await server.start()
            self.servers[name] = server
        self.proposals = self.root / "proposals"
        self.commits = self.root / "commits"
        self.proposals.mkdir()
        self.commits.mkdir()
        self.cert1 = huc.sha256(b"BFT-P2P-CERT-1")
        self.cc1 = huc.sha256(b"BFT-P2P-CC-1")
        self.cert2 = huc.sha256(b"BFT-P2P-CERT-2")
        self.cc2 = huc.sha256(b"BFT-P2P-CC-2")

    async def asyncTearDown(self):
        for server in self.servers.values():
            await server.close()
        self.tmp.cleanup()

    def make_proposal(self, action="ISSUE", cert=None, cc=None, previous=None, label="proposal"):
        path = self.proposals / f"{label}-{len(list(self.proposals.iterdir()))}.json"
        bft.create_operation_proposal(
            self.nodes["BFT-A"], action, cert or self.cert1, cc or self.cc1, path,
            previous_certificate_sha256=previous,
            metadata={"reason": "p2p-test-revocation"} if action == "REVOKE" else {},
        )
        return path

    async def test_real_tcp_p2p_runs_all_bft_phases_and_replicates(self):
        proposal = self.make_proposal(label="issue")
        result = await bft_peer.broadcast_consensus(
            self.nodes["BFT-A"], proposal, self.commits / "issue.commit.json", timeout=1.0
        )
        self.assertEqual(result["result"], "bft_commit_replicated")
        self.assertEqual(result["prepare_votes"], 4)
        self.assertEqual(result["prepared_lock_acks"], 4)
        self.assertEqual(result["commit_votes"], 4)
        statuses = [bft.status(n) for n in self.nodes.values()]
        self.assertEqual({s["sequence"] for s in statuses}, {1})
        self.assertEqual(len({s["head_hash"] for s in statuses}), 1)

    async def test_view_change_and_prepared_recovery_over_tcp(self):
        # A (view-0 primary) proposes and A/B/C persist prepared-lock evidence.
        proposal = self.make_proposal(label="prepared-before-failover")
        pp_path = self.root / "preprepare.json"
        bft.create_preprepare(self.nodes["BFT-A"], proposal, pp_path)
        pp = rsp._read(pp_path)
        prepare_votes = [bft.accept_preprepare(self.nodes[x], pp) for x in ("BFT-A", "BFT-B", "BFT-C")]
        net = rsp.load_network(self.nodes["BFT-A"])
        prepare_cert = bft.assemble_prepare_certificate(net, bft.load_state(self.nodes["BFT-A"]), pp, prepare_votes)
        for name in ("BFT-A", "BFT-B", "BFT-C"):
            bft.create_prepared_ack(self.nodes[name], prepare_cert)

        # The old primary disappears. B becomes primary for view 1 and collects
        # three signed VIEW_CHANGE messages over actual TCP peer connections.
        await self.servers["BFT-A"].close()
        new_view_path = self.root / "new-view.json"
        # Windows hosted runners have higher event-loop and process scheduling jitter.
        # Use a larger network deadline without weakening quorum or safety assertions.
        network_timeout = 4.0 if sys.platform == "win32" else 1.5
        new_view_result = await bft_peer.advance_view(
            self.nodes["BFT-B"], new_view_path, timeout=network_timeout, reason="primary-unreachable"
        )
        self.assertEqual(new_view_result["view"], 1)
        self.assertEqual(new_view_result["primary_id"], "BFT-B")
        self.assertEqual(len(new_view_result["new_view_installed_on"]), 2)

        # Keep the old primary offline while the new quorum recovers and commits.
        # It will later catch up by requesting the verified BFT state package.

        # New primary B recovers the highest prepared request in view 1.
        recovered = await bft_peer.recover_prepared(
            self.nodes["BFT-B"], self.commits / "recovered.commit.json", timeout=network_timeout
        )
        self.assertEqual(recovered["result"], "bft_commit_replicated")
        self.assertEqual(recovered["recovery"], "re-proposed highest PreparedCertificate selected by NEW_VIEW")
        # The old primary is still at genesis while B/C/D have committed.
        self.assertEqual(bft.status(self.nodes["BFT-A"])["sequence"], 0)
        server_a = peer.PeerServer(self.nodes["BFT-A"], "127.0.0.1", self.ports["BFT-A"])
        await server_a.start()
        self.servers["BFT-A"] = server_a
        synced = await bft_peer.sync_from_peer(self.nodes["BFT-A"], "BFT-B", timeout=network_timeout)
        self.assertEqual(synced["result"], "bft_state_synchronized")
        states = [bft.status(n) for n in self.nodes.values()]
        self.assertEqual({s["sequence"] for s in states}, {1})
        self.assertEqual(len({s["head_hash"] for s in states}), 1)
        self.assertEqual({s["view"] for s in states}, {1})

    async def test_partition_below_quorum_does_not_commit(self):
        await self.servers["BFT-C"].close()
        await self.servers["BFT-D"].close()
        proposal = self.make_proposal(label="partition-no-quorum")
        with self.assertRaisesRegex(RuntimeError, "Quórum PREPARE insuficiente"):
            await bft_peer.broadcast_consensus(
                self.nodes["BFT-A"], proposal, self.commits / "no-quorum.json", timeout=0.2
            )
        self.assertEqual({bft.status(n)["sequence"] for n in self.nodes.values()}, {0})

    async def test_invalid_phase_message_is_rejected_by_remote_validator(self):
        malformed = None
        with self.assertRaisesRegex(ValueError, "BFT_PRE_PREPARE requiere preprepare"):
            await peer.send_request(self.nodes["BFT-A"], "BFT-B", "BFT_PRE_PREPARE",
                                    {"preprepare": malformed}, timeout=1.0)

    async def test_node_b_cannot_create_preprepare_when_not_primary(self):
        proposal = self.make_proposal(label="non-primary")
        with self.assertRaisesRegex(ValueError, "Solo BFT-A puede emitir PRE-PREPARE"):
            bft.create_preprepare(self.nodes["BFT-B"], proposal, self.root / "not-primary.json")

    async def test_peer_message_replay_is_rejected(self):
        envelope = peer._make_envelope(self.nodes["BFT-A"], "PING", {})
        payload = peer._verify_envelope(rsp.load_network(self.nodes["BFT-B"]), envelope)
        message_id = payload["message_id"]
        peer._remember_message_id(self.nodes["BFT-B"], message_id)
        with self.assertRaisesRegex(ValueError, "Mensaje P2P repetido"):
            peer._remember_message_id(self.nodes["BFT-B"], message_id)


if __name__ == "__main__":
    unittest.main(verbosity=2)
