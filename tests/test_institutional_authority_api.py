import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from huc_institutional_authority import AuthorityStore, build_server
from huc_x509_external import create_single_use_authorization, fingerprint


def issue(subject, issuer, issuer_key, *, ca=False, server=False):
    from datetime import datetime, timedelta, timezone
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer.subject if issuer else name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(minutes=2)).not_valid_after(now+timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=1 if ca else None), critical=True))
    if not ca:
        builder = builder.add_extension(x509.KeyUsage(digital_signature=True,
            content_commitment=True, key_encipherment=True, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=None, decipher_only=None), critical=True)
        eku = ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH
        builder = builder.add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        if server:
            builder = builder.add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))
            ]), critical=False)
    cert = builder.sign(issuer_key if issuer else key, hashes.SHA256())
    return cert, key


def write_pem(path, data):
    path.write_bytes(data)
    path.chmod(0o600)


class InstitutionalAuthorityAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ca, self.ca_key = issue("HUC synthetic test CA", None, None, ca=True)
        self.server_cert, self.server_key = issue("localhost", self.ca, self.ca_key, server=True)
        self.clients = []
        for name in ("LEGISLATIVE_ASSEMBLY", "EXECUTIVE_POWER",
                     "JUDICIAL_POWER", "SUPREME_ELECTORAL_TRIBUNAL"):
            cert, key = issue(name, self.ca, self.ca_key)
            self.clients.append((name, cert, key))
        self.ca_file = self.root/"ca.crt"
        self.crl_file = self.root/"ca.crl"
        self.server_cert_file = self.root/"server.crt"
        self.server_key_file = self.root/"server.key"
        write_pem(self.ca_file, self.ca.public_bytes(serialization.Encoding.PEM))
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        crl = (x509.CertificateRevocationListBuilder().issuer_name(self.ca.subject)
            .last_update(now-timedelta(minutes=1)).next_update(now+timedelta(days=1))
            .sign(self.ca_key, hashes.SHA256()))
        write_pem(self.crl_file, crl.public_bytes(serialization.Encoding.PEM))
        write_pem(self.server_cert_file, self.server_cert.public_bytes(serialization.Encoding.PEM))
        write_pem(self.server_key_file, self.server_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
        self.registry_file = self.root/"clients.json"
        self.registry_file.write_text(json.dumps({"clients": {
            fingerprint(cert): name for name, cert, _ in self.clients
        }}), encoding="utf-8")
        self.db = self.root/"authority.sqlite3"
        self.server = build_server(self.db, self.server_cert_file, self.server_key_file,
                                   self.ca_file, self.registry_file, "127.0.0.1", 0,
                                   self.ca_file, self.crl_file, None, "crl")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"https://127.0.0.1:{self.server.server_port}"
        import ssl
        self.contexts = []
        for name, cert, key in self.clients:
            cert_file = self.root/f"{name}.crt"
            key_file = self.root/f"{name}.key"
            write_pem(cert_file, cert.public_bytes(serialization.Encoding.PEM))
            write_pem(key_file, key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
            ctx = ssl.create_default_context(cafile=str(self.ca_file))
            ctx.load_cert_chain(str(cert_file), str(key_file))
            self.contexts.append(ctx)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.tmp.cleanup()

    def request(self, index, path, payload=None):
        if payload is not None and "authorization" in payload:
            payload = {**payload,
                "signer_certificate_pem": self.clients[index][1].public_bytes(
                    serialization.Encoding.PEM).decode("ascii"),
                "signer_chain_pem": []}
        data = None if payload is None else json.dumps(payload).encode()
        req = urllib.request.Request(self.url+path, data=data,
            headers={"Content-Type": "application/json"} if data else {})
        return urllib.request.urlopen(req, context=self.contexts[index], timeout=5)

    def test_four_independent_mtls_clients_are_enrolled(self):
        for i, (name, _, _) in enumerate(self.clients):
            with self.subTest(institution=name):
                body = json.loads(self.request(i, "/health").read())
                self.assertEqual(body["institution_id"], name)

    def test_one_shared_authority_rejects_cross_institution_double_consume(self):
        authorizations = []
        for i, (name, cert, key) in enumerate(self.clients):
            authorizations.append(create_single_use_authorization(cert, key,
                outpoint="shared-utxo:0", operation="APPROVE",
                resource_id="synthetic-case-01", expires_at=int(time.time())+600,
                nonce=f"four-institution-test-{i}"))
        def attempt(i):
            try:
                with self.request(i, "/v1/consume",
                                  {"authorization": authorizations[i]}) as response:
                    return response.status
            except urllib.error.HTTPError as exc:
                return exc.code
        with ThreadPoolExecutor(max_workers=4) as pool:
            statuses = list(pool.map(attempt, range(4)))
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(409), 3)

    def test_evidence_chain_is_valid_and_survives_authority_restart(self):
        name, cert, key = self.clients[2]
        auth = create_single_use_authorization(cert, key, outpoint="restart-utxo:0",
            operation="SIGN", resource_id="synthetic-document-02",
            expires_at=int(time.time())+600, nonce="restart-test")
        with self.request(2, "/v1/consume", {"authorization": auth}):
            pass
        evidence = json.loads(self.request(0, "/v1/evidence").read())
        self.assertTrue(evidence["event_chain_valid"])
        self.assertEqual(evidence["event_count"], 1)
        # Simulate process restart by reopening the same durable database.
        reopened = AuthorityStore(self.db)
        persisted = reopened.evidence()
        self.assertTrue(persisted["event_chain_valid"])
        self.assertEqual(persisted["event_head_hash"], evidence["event_head_hash"])
        with self.assertRaises(ValueError):
            reopened.consume(auth, cert, name)

    def test_untrusted_client_ca_is_not_accepted_by_tls(self):
        import ssl
        ctx = ssl.create_default_context()
        req = urllib.request.Request(self.url+"/health")
        with self.assertRaises((urllib.error.URLError, ssl.SSLError)):
            urllib.request.urlopen(req, context=ctx, timeout=5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
