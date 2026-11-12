import asyncio
import json
import socket
import tempfile
import unittest
from pathlib import Path

import huc
import huc_replicated as rsp
import huc_peer as peer
import huc_view as view
import huc_membership as membership


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class PeerNetworkTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.nodes = {}
        public = []
        for name in ("PEER-A", "PEER-B", "PEER-C", "PEER-D"):
            node = self.root / name
            rsp.node_init(name, node)
            self.nodes[name] = node
            public.append(node / rsp.NODE_PUBLIC)
        self.network_path = self.root / "network.json"
        result = rsp.create_network(public, self.network_path, 1)
        self.network_pin = result["network_sha256"]
        for node in self.nodes.values():
            rsp.node_join(node, self.network_path, self.network_pin)
        self.ports = {name: free_port() for name in self.nodes}
        endpoints = [f"{name}=127.0.0.1:{port}" for name, port in self.ports.items()]
        self.peer_map_path = self.root / "peer-map.json"
        peer_map_result = peer.create_peer_map(self.network_path, self.network_pin, endpoints, self.peer_map_path)
        self.peer_map_pin = peer_map_result["peer_map_sha256"]
        for node in self.nodes.values():
            peer.install_peer_map(node, self.peer_map_path, self.peer_map_pin)
        self.servers = {}
        for name, node in self.nodes.items():
            server = peer.PeerServer(node, "127.0.0.1", self.ports[name])
            await server.start()
            self.servers[name] = server
        self.proposals = self.root / "proposals"
        self.commits = self.root / "commits"
        self.proposals.mkdir(); self.commits.mkdir()

    async def asyncTearDown(self):
        for server in self.servers.values():
            await server.close()
        self.tmp.cleanup()

    def make_proposal(self, proposer="PEER-A", label="p"):
        raw = self.proposals / f"{label}-raw.json"
        annotated = self.proposals / f"{label}.json"
        rsp.create_proposal(self.nodes[proposer], "ISSUE", (label.encode().hex()[:64]).ljust(64, "1"),
                            ("a" * 64), raw)
        view.annotate_proposal_for_view(self.nodes[proposer], raw, annotated)
        return annotated

    async def test_signed_ping_between_independent_nodes(self):
        results = await peer.peer_status(self.nodes["PEER-A"], 1.0, None)
        self.assertEqual({x["status"] for x in results.values()}, {"ONLINE", "LOCAL"})

    async def test_p2p_proposal_vote_commit_and_replication(self):
        proposal = self.make_proposal(label="issue")
        commit_path = self.commits / "issue.commit.json"
        result = await peer.broadcast_proposal(self.nodes["PEER-A"], proposal, commit_path, 1.0, None)
        self.assertEqual(result["votes_collected"], 4)
        states = [rsp.node_status(self.nodes[name]) for name in self.nodes]
        self.assertEqual({x["sequence"] for x in states}, {1})
        self.assertEqual(len({x["head_hash"] for x in states}), 1)

    async def test_three_nodes_continue_when_one_peer_is_offline_then_sync(self):
        await self.servers["PEER-D"].close()
        proposal = self.make_proposal(label="offline")
        result = await peer.broadcast_proposal(self.nodes["PEER-A"], proposal,
                                               self.commits / "offline.commit.json", 0.5, None)
        self.assertEqual(result["votes_collected"], 3)
        self.assertEqual(rsp.node_status(self.nodes["PEER-D"])["sequence"], 0)
        await peer.sync_from_peer(self.nodes["PEER-D"], "PEER-A", 1.0, None)
        self.assertEqual(rsp.node_status(self.nodes["PEER-D"])["sequence"], 1)

    async def test_view_change_recovers_when_current_primary_is_offline(self):
        await self.servers["PEER-A"].close()
        cert_path = self.root / "view-1.json"
        result = await peer.advance_view(self.nodes["PEER-B"], cert_path, 0.5, None)
        self.assertEqual(result["target_view"], 1)
        self.assertEqual(result["primary_id"], "PEER-B")
        self.assertEqual(result["valid_messages"], 3)
        # Bring the old primary back and install the new-view certificate.
        server_a = peer.PeerServer(self.nodes["PEER-A"], "127.0.0.1", self.ports["PEER-A"])
        await server_a.start()
        self.servers["PEER-A"] = server_a
        cert = rsp._read(cert_path)
        await peer.send_request(self.nodes["PEER-B"], "PEER-A", "NEW_VIEW_CERTIFICATE", {"certificate": cert}, 1.0)
        proposal = self.make_proposal(proposer="PEER-B", label="after-view")
        result2 = await peer.broadcast_proposal(self.nodes["PEER-B"], proposal,
                                                self.commits / "after-view.commit.json", 1.0, None)
        self.assertEqual(result2["votes_collected"], 4)
        self.assertEqual({rsp.node_status(n)["sequence"] for n in self.nodes.values()}, {1})

    async def test_envelope_tampering_is_rejected(self):
        envelope = peer._make_envelope(self.nodes["PEER-A"], "PING", {})
        envelope["payload"]["body"]["injected"] = True
        with self.assertRaisesRegex(ValueError, "Firma de mensaje P2P inválida"):
            peer._verify_envelope(rsp.load_network(self.nodes["PEER-B"]), envelope)

    async def test_peer_map_pin_prevents_endpoint_substitution(self):
        changed = rsp._read(self.peer_map_path)
        changed["endpoints"]["PEER-B"]["port"] = 1
        bad_path = self.root / "changed-peer-map.json"
        huc.write_json(bad_path, changed)
        with self.assertRaises(ValueError):
            peer.install_peer_map(self.nodes["PEER-A"], bad_path, self.peer_map_pin)

    async def test_membership_proposal_and_successor_package_are_distributed_over_p2p(self):
        new_node = self.root / "PEER-E"
        rsp.node_init("PEER-E", new_node)
        join_request = self.root / "peer-e-join.json"
        membership.create_join_request(new_node, join_request, self.network_path)
        proposal = self.root / "membership-proposal.json"
        membership.create_membership_proposal(
            self.nodes["PEER-A"], [join_request], ["PEER-A"], proposal
        )
        package_path = self.root / "membership-package.json"
        result = await peer.broadcast_membership_proposal(
            self.nodes["PEER-A"], proposal, package_path, 1.0, None
        )
        self.assertEqual(result["votes_collected"], 4)
        self.assertEqual(set(result["staged_on"]), {"PEER-B", "PEER-C", "PEER-D"})
        package = rsp._read(package_path)
        for name in ("PEER-B", "PEER-C", "PEER-D"):
            inbox = self.nodes[name] / "membership-inbox"
            staged_files = list(inbox.glob("membership-*.json"))
            self.assertEqual(len(staged_files), 1)
            self.assertEqual(rsp._read(staged_files[0]), package)
        for server in self.servers.values():
            await server.close()
        for name in ("PEER-B", "PEER-C", "PEER-D"):
            membership.activate_membership(self.nodes[name], package_path)
        membership.join_successor_network(new_node, package_path)
        self.assertEqual(rsp.load_network(self.nodes["PEER-B"])["network_id"],
                         rsp.load_network(new_node)["network_id"])

    async def test_non_loopback_server_requires_tls_or_explicit_private_network_override(self):
        with self.assertRaisesRegex(ValueError, "configurar TLS"):
            peer.PeerServer(self.nodes["PEER-A"], "0.0.0.0", self.ports["PEER-A"])

    async def test_replay_cache_rejects_duplicate_message_id(self):
        peer._remember_message_id(self.nodes["PEER-A"], "message-duplicate-0001")
        with self.assertRaisesRegex(ValueError, "anti-replay"):
            peer._remember_message_id(self.nodes["PEER-A"], "message-duplicate-0001")


if __name__ == "__main__":
    unittest.main(verbosity=2)
