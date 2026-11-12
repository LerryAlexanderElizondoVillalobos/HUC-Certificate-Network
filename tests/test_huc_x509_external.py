import tempfile
import time
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from huc_x509_external import (
    SingleUseUTXORegistry, create_single_use_authorization,
    verify_government_certificate, verify_single_use_authorization,
)


def make_chain():
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "HUC TEST ROOT ONLY")])
    root = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
        .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - __import__("datetime").timedelta(minutes=1))
        .not_valid_after(now + __import__("datetime").timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), critical=True)
        .sign(root_key, hashes.SHA256()))
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic Public Officer")])
    leaf = (x509.CertificateBuilder().subject_name(leaf_name).issuer_name(root.subject)
        .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - __import__("datetime").timedelta(minutes=1))
        .not_valid_after(now + __import__("datetime").timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=False, crl_sign=False, encipher_only=None, decipher_only=None), critical=True)
        .sign(root_key, hashes.SHA256()))
    return root, leaf, leaf_key


class GovernmentX509AdapterTests(unittest.TestCase):
    def setUp(self):
        self.root, self.leaf, self.key = make_chain()

    def test_accepts_certificate_chained_to_explicit_test_anchor(self):
        result = verify_government_certificate(self.leaf, [], [self.root])
        self.assertTrue(result["chain_valid"])
        self.assertEqual(result["revocation_status"], "NOT_CHECKED")
        self.assertFalse(result["production_ready"])

    def test_rejects_untrusted_root(self):
        other, _, _ = make_chain()
        with self.assertRaisesRegex(ValueError, "terminate|signature"):
            verify_government_certificate(self.leaf, [], [other])

    def test_authorization_is_bound_to_certificate_and_signature(self):
        auth = create_single_use_authorization(self.leaf, self.key,
            outpoint="demo:0", operation="PAYMENT", resource_id="invoice-demo-001",
            expires_at=int(time.time()) + 600, nonce="test-nonce-001")
        self.assertTrue(verify_single_use_authorization(auth, self.leaf)["signature_valid"])
        auth["payload"]["resource_id"] = "invoice-other"
        with self.assertRaisesRegex(ValueError, "signature"):
            verify_single_use_authorization(auth, self.leaf)

    def test_utxo_can_only_be_consumed_once(self):
        auth = create_single_use_authorization(self.leaf, self.key,
            outpoint="demo:1", operation="DOCUMENT_ISSUE", resource_id="record-001",
            expires_at=int(time.time()) + 600, nonce="test-nonce-002")
        with tempfile.TemporaryDirectory() as tmp:
            registry = SingleUseUTXORegistry(Path(tmp) / "utxo.sqlite3")
            self.assertTrue(registry.consume(auth, self.leaf)["consumed"])
            with self.assertRaisesRegex(ValueError, "already consumed"):
                registry.consume(auth, self.leaf)

    def test_rejects_expired_authorization(self):
        auth = create_single_use_authorization(self.leaf, self.key,
            outpoint="demo:2", operation="APPROVE", resource_id="case-001",
            expires_at=int(time.time()) + 1, nonce="test-nonce-003")
        auth["payload"]["expires_at"] = int(time.time()) - 1
        with self.assertRaisesRegex(ValueError, "expired"):
            verify_single_use_authorization(auth, self.leaf)


if __name__ == "__main__":
    unittest.main()
