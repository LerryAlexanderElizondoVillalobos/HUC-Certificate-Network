import asyncio
import ipaddress
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

import huc
import huc_bft as bft
import huc_bft_peer as bft_peer
import huc_peer as peer
import huc_replicated as rsp


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def write_key(key, path: Path):
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def create_test_tls_ca(folder: Path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "HUC Local Test TLS CA")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=2)).not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256()))
    ca_path = folder / "tls-test-ca.pem"
    ca_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert, ca_path


def create_server_cert(ca_key, ca_cert, folder: Path, node_id: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{node_id}.huc.test")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(ca_cert.subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=2)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            x509.DNSName("localhost"),
        ]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256()))
    cert_path, key_path = folder / f"{node_id}-server.pem", folder / f"{node_id}-server.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    write_key(key, key_path)
    return cert_path, key_path


class BFTSeparateProcessTLSClusterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.processes = []
        self.nodes = {}
        public = []
        for name in ("PROC-A", "PROC-B", "PROC-C", "PROC-D"):
            node = self.root / name
            rsp.node_init(name, node)
            self.nodes[name] = node
            public.append(node / rsp.NODE_PUBLIC)
        self.network_path = self.root / "network.json"
        network_info = rsp.create_network(public, self.network_path, fault_tolerance=1)
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
        ca_key, ca_cert, self.tls_ca = create_test_tls_ca(self.root)
        for name, node in self.nodes.items():
            tls_cert, tls_key = create_server_cert(ca_key, ca_cert, self.root, name)
            log = open(self.root / f"{name}.log", "wb")
            proc = subprocess.Popen([
                sys.executable, str(Path(peer.__file__).resolve()), "serve",
                "--node-dir", str(node), "--bind-host", "127.0.0.1",
                "--port", str(self.ports[name]), "--tls-cert", str(tls_cert),
                "--tls-key", str(tls_key),
            ], cwd=str(Path(peer.__file__).resolve().parent), stdout=log, stderr=subprocess.STDOUT)
            self.processes.append((proc, log))
        # Wait until every separate process accepts TLS and authenticated PING.
        deadline = time.monotonic() + 10
        last_statuses = None
        while time.monotonic() < deadline:
            if any(proc.poll() is not None for proc, _ in self.processes):
                logs = {name: (self.root / f"{name}.log").read_text(errors="replace") for name in self.nodes}
                raise RuntimeError(f"Un servidor de nodo terminó al arrancar: {logs}")
            try:
                last_statuses = asyncio.run(peer.peer_status(self.nodes["PROC-A"], 0.4, self.tls_ca))
                if all(v["status"] in {"ONLINE", "LOCAL"} for v in last_statuses.values()):
                    break
            except Exception as exc:
                last_statuses = {"exception": str(exc)}
            time.sleep(0.1)
        else:
            logs = {name: (self.root / f"{name}.log").read_text(errors="replace") for name in self.nodes}
            raise RuntimeError(f"Los cuatro servidores P2P no quedaron listos; status={last_statuses}; logs={logs}")

    def tearDown(self):
        for proc, log in self.processes:
            if proc.poll() is None:
                proc.terminate()
        for proc, log in self.processes:
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.wait(timeout=3)
            log.close()
        self.tmp.cleanup()

    def test_bft_round_trip_over_tls_between_four_processes(self):
        proposal = self.root / "proposal.json"
        bft.create_operation_proposal(
            self.nodes["PROC-A"], "ISSUE", huc.sha256(b"process-certificate"),
            huc.sha256(b"process-consensus"), proposal,
        )
        result = asyncio.run(bft_peer.broadcast_consensus(
            self.nodes["PROC-A"], proposal, self.root / "commit.json",
            timeout=2.0, tls_ca=self.tls_ca,
        ))
        self.assertEqual(result["result"], "bft_commit_replicated")
        states = [bft.status(node) for node in self.nodes.values()]
        self.assertEqual({item["sequence"] for item in states}, {1})
        self.assertEqual(len({item["head_hash"] for item in states}), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
