import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from huc_x509_external import SingleUseUTXORegistry, create_single_use_authorization


def make_identity():
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "HUC Local Mode Test")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - __import__("datetime").timedelta(minutes=1))
        .not_valid_after(now + __import__("datetime").timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=False, crl_sign=False, encipher_only=None, decipher_only=None), critical=True)
        .sign(key, hashes.SHA256()))
    return cert, key


class LinuxStandaloneModeTests(unittest.TestCase):
    def test_local_registry_works_without_any_node_configuration(self):
        cert, key = make_identity()
        auth = create_single_use_authorization(cert, key, outpoint="offline:0",
            operation="APPROVE", resource_id="local-test", expires_at=int(time.time()) + 600,
            nonce="offline-mode")
        with tempfile.TemporaryDirectory() as tmp:
            registry = SingleUseUTXORegistry(Path(tmp) / "huc-local.sqlite3")
            result = registry.consume(auth, cert)
            self.assertTrue(result["consumed"])
            self.assertTrue(result["single_use_enforced"])

    def test_concurrent_consumption_across_registry_instances_has_one_winner(self):
        cert, key = make_identity()
        auth = create_single_use_authorization(cert, key, outpoint="shared:0",
            operation="PAYMENT", resource_id="concurrency-test",
            expires_at=int(time.time()) + 600, nonce="concurrent-mode")
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "shared.sqlite3"
            registries = [SingleUseUTXORegistry(db) for _ in range(4)]
            barrier = threading.Barrier(4)

            def attempt(registry):
                barrier.wait()
                try:
                    registry.consume(auth, cert)
                    return "CONSUMED"
                except ValueError as exc:
                    if "already consumed" in str(exc):
                        return "REJECTED"
                    raise

            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(attempt, registries))
            self.assertEqual(results.count("CONSUMED"), 1)
            self.assertEqual(results.count("REJECTED"), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
