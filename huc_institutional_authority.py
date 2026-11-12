"""Linux User Mode HUC Institutional Authority API (HTTPS + mandatory mTLS).

Single logical authority; SQLite is the shared source of truth for every client.
This is a pilot implementation, not a certified production PKI/revocation service.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import ssl
import stat
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography import x509
from huc_x509_external import canonical, fingerprint, verify_single_use_authorization
from huc_x509_policy import validate_certificate_policy

ZERO = "0" * 64
MAX_BODY = 64 * 1024


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


class AuthorityStore:
    """Durable, atomic single-use registry plus tamper-evident event journal."""
    def __init__(self, database: str | Path):
        self.path = Path(database).expanduser()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.exists() or self.path.is_symlink():
            info = self.path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise RuntimeError("Database path must be a regular file, not a symlink")
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                raise PermissionError("Database must belong to the service user")
        self.anchor_path = self.path.with_suffix(self.path.suffix + ".anchor.json")
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("""CREATE TABLE IF NOT EXISTS consumed (
                outpoint TEXT PRIMARY KEY, txid TEXT NOT NULL UNIQUE,
                authorization_sha256 TEXT NOT NULL, institution_id TEXT NOT NULL,
                consumed_at INTEGER NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS events (
                sequence INTEGER PRIMARY KEY, event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL, previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL UNIQUE)""")
        os.chmod(self.path, 0o600)
        self._verify_and_reconcile_anchor()

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=20, isolation_level=None)
        db.execute("PRAGMA busy_timeout=20000")
        db.execute("PRAGMA synchronous=FULL")
        return db


    def _atomic_write_anchor(self, sequence: int, head_hash: str) -> None:
        self.anchor_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = {"schema": "HUC-ROLLBACK-ANCHOR-1",
                   "sequence": sequence, "head_hash": head_hash}
        fd, temp_name = tempfile.mkstemp(prefix=".huc-anchor-", dir=self.anchor_path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temp_name, 0o600)
            os.replace(temp_name, self.anchor_path)
            dir_fd = os.open(self.anchor_path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def _verify_and_reconcile_anchor(self) -> None:
        evidence = self.evidence()
        if not evidence["event_chain_valid"]:
            raise RuntimeError("Evidence chain is corrupt; authority startup refused")
        sequence = evidence["event_count"]
        head_hash = evidence["event_head_hash"]
        if self.anchor_path.exists():
            anchor = json.loads(self.anchor_path.read_text(encoding="utf-8"))
            if anchor.get("schema") != "HUC-ROLLBACK-ANCHOR-1":
                raise RuntimeError("Rollback anchor schema invalid; startup refused")
            anchored_sequence = anchor.get("sequence")
            anchored_hash = anchor.get("head_hash")
            if not isinstance(anchored_sequence, int) or not isinstance(anchored_hash, str):
                raise RuntimeError("Rollback anchor malformed; startup refused")
            if sequence < anchored_sequence:
                raise RuntimeError("Database rollback detected; authority startup refused")
            if sequence == anchored_sequence and head_hash != anchored_hash:
                raise RuntimeError("Database fork/rollback detected; authority startup refused")
        self._atomic_write_anchor(sequence, head_hash)

    def consume(self, authorization: dict[str, Any], cert: x509.Certificate,
                institution_id: str) -> dict[str, Any]:
        verified = verify_single_use_authorization(authorization, cert)
        outpoint = verified["outpoint"]
        auth_hash = _digest(authorization)
        txid = _digest({"outpoint": outpoint, "authorization_sha256": auth_hash})
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                now = int(time.time())
                db.execute("INSERT INTO consumed VALUES (?, ?, ?, ?, ?)",
                           (outpoint, txid, auth_hash, institution_id, now))
                previous_row = db.execute(
                    "SELECT event_hash FROM events ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                previous = previous_row[0] if previous_row else ZERO
                seq = db.execute("SELECT COUNT(*) FROM events").fetchone()[0] + 1
                payload = {
                    "outpoint": outpoint, "txid": txid,
                    "authorization_sha256": auth_hash,
                    "institution_id": institution_id,
                    "client_certificate_sha256": fingerprint(cert),
                    "operation": verified["operation"],
                    "resource_id": verified["resource_id"],
                    "consumed_at": now,
                }
                body = {"sequence": seq, "event_type": "UTXO_CONSUMED",
                        "payload": payload, "previous_hash": previous}
                event_hash = _digest(body)
                db.execute("INSERT INTO events VALUES (?, ?, ?, ?, ?)",
                    (seq, "UTXO_CONSUMED", canonical(payload).decode(),
                     previous, event_hash))
                db.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                db.execute("ROLLBACK")
                raise ValueError("UTXO already consumed: double-use rejected") from exc
            except Exception:
                db.execute("ROLLBACK")
                raise
        self._atomic_write_anchor(seq, event_hash)
        return {"consumed": True, "single_use_enforced": True,
                "institution_id": institution_id, "outpoint": outpoint,
                "txid": txid, "event_hash": event_hash}

    def evidence(self) -> dict[str, Any]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT sequence,event_type,payload_json,previous_hash,event_hash "
                "FROM events ORDER BY sequence"
            ).fetchall()
        events = []
        previous = ZERO
        valid = True
        for expected, (seq, kind, payload_json, prev, event_hash) in enumerate(rows, 1):
            payload = json.loads(payload_json)
            body = {"sequence": seq, "event_type": kind,
                    "payload": payload, "previous_hash": prev}
            if seq != expected or prev != previous or _digest(body) != event_hash:
                valid = False
            events.append({**body, "event_hash": event_hash})
            previous = event_hash
        return {"schema": "HUC-AUTHORITY-EVIDENCE-1",
                "event_count": len(events), "event_head_hash": previous,
                "event_chain_valid": valid, "events": events}


def load_client_registry(path: str | Path) -> dict[str, str]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    clients = raw.get("clients")
    if not isinstance(clients, dict) or not clients:
        raise ValueError("Client registry must contain a non-empty 'clients' object")
    normalized = {}
    for cert_fp, institution in clients.items():
        fp = cert_fp.lower()
        if len(fp) != 64 or any(c not in "0123456789abcdef" for c in fp):
            raise ValueError("Client registry keys must be SHA-256 certificate fingerprints")
        if not isinstance(institution, str) or not institution.strip():
            raise ValueError("Institution identifiers must be non-empty strings")
        normalized[fp] = institution
    return normalized


def build_server(database: str | Path, cert_file: str | Path,
                 key_file: str | Path, client_ca_file: str | Path,
                 client_registry_file: str | Path, host: str = "127.0.0.1",
                 port: int = 8443, trust_bundle: str | Path | None = None,
                 crl_bundle: str | Path | None = None, policy_oid: str | None = None,
                 revocation: str = "crl"):
    store = AuthorityStore(database)
    clients = load_client_registry(client_registry_file)
    if trust_bundle is None or crl_bundle is None:
        raise ValueError("Signer trust bundle and CRL bundle are mandatory; revocation must fail closed")

    class Handler(BaseHTTPRequestHandler):
        server_version = "HUC-Institutional-Authority/0.8.0"
        def log_message(self, fmt, *args):
            # Avoid logging authorization bodies, certificate data, or secrets.
            print("huc-authority", self.client_address[0], fmt % args)

        def _json(self, status: int, value: dict[str, Any]):
            data = canonical(value)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _institution(self):
            raw = self.connection.getpeercert(binary_form=True)
            if not raw:
                raise PermissionError("mTLS client certificate required")
            cert = x509.load_der_x509_certificate(raw)
            institution = clients.get(fingerprint(cert))
            if not institution:
                raise PermissionError("Client certificate is not enrolled")
            return cert, institution

        def do_GET(self):
            try:
                _, institution = self._institution()
                if self.path == "/health":
                    return self._json(200, {"status": "ok", "mode": "institutional",
                                             "institution_id": institution})
                if self.path == "/v1/evidence":
                    return self._json(200, store.evidence())
                return self._json(404, {"error": "not_found"})
            except PermissionError as exc:
                return self._json(403, {"error": str(exc)})
            except Exception:
                return self._json(500, {"error": "internal_error"})

        def do_POST(self):
            if self.path != "/v1/consume":
                return self._json(404, {"error": "not_found"})
            try:
                cert, institution = self._institution()
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > MAX_BODY:
                    return self._json(413, {"error": "invalid_request_size"})
                request = json.loads(self.rfile.read(length))
                signer_raw = request["signer_certificate_pem"].encode("utf-8")
                signer_cert = x509.load_pem_x509_certificate(signer_raw)
                chain = [x509.load_pem_x509_certificate(item.encode("utf-8"))
                         for item in request.get("signer_chain_pem", [])]
                validate_certificate_policy(signer_cert, chain, trust_bundle,
                    crl_bundle=crl_bundle, policy_oid=policy_oid, revocation=revocation)
                result = store.consume(request["authorization"], signer_cert, institution)
                return self._json(201, result)
            except PermissionError as exc:
                return self._json(403, {"error": str(exc)})
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                return self._json(409 if "already consumed" in str(exc) else 400,
                                  {"error": str(exc)})
            except Exception:
                return self._json(500, {"error": "internal_error"})

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(cert_file), str(key_file))
    context.load_verify_locations(cafile=str(client_ca_file))
    # mTLS client certificates are also checked against the provisioned CRL.
    context.load_verify_locations(cafile=str(crl_bundle))
    if not hasattr(ssl, "VERIFY_CRL_CHECK_CHAIN"):
        raise RuntimeError("This Python/OpenSSL build cannot enforce full-chain CRL checking")
    context.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN
    context.verify_mode = ssl.CERT_REQUIRED
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.huc_store = store
    return server


def main():
    parser = argparse.ArgumentParser(description="HUC 0.8.0 Linux institutional HTTPS/mTLS authority")
    parser.add_argument("--database", default=str(Path.home()/".local/state/huc/authority.sqlite3"))
    parser.add_argument("--server-cert", required=True)
    parser.add_argument("--server-key", required=True)
    parser.add_argument("--client-ca", required=True)
    parser.add_argument("--client-registry", required=True)
    parser.add_argument("--trust-bundle", required=True)
    parser.add_argument("--crl-bundle", required=True)
    parser.add_argument("--policy-oid")
    parser.add_argument("--revocation", choices=["crl", "ocsp", "both"], default="crl")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()
    server = build_server(args.database, args.server_cert, args.server_key,
        args.client_ca, args.client_registry, args.host, args.port,
        args.trust_bundle, args.crl_bundle, args.policy_oid, args.revocation)
    print(f"HUC authority listening on https://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
