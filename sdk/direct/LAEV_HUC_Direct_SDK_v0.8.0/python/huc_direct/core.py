from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from filelock import FileLock, Timeout
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.x509.oid import NameOID

SDK_VERSION = "0.8.0"
POLICY_SCHEMA = "LAEV-HUC-POLICY-1"
ANCHOR_SCHEMA = "LAEV-HUC-ANCHOR-1"
LEDGER_SCHEMA = "LAEV-HUC-UTXO-1"
CC_TYPE = "LAEV-HUC-CC"
CC_VERSION = "1"
STATE_SCHEMA = "LAEV-HUC-STATE-1"
PACKAGE_SCHEMA = "LAEV-HUC-PACKAGE-1"
CHALLENGE_SCHEMA = "LAEV-HUC-DIRECT-CHALLENGE-1"
RESPONSE_SCHEMA = "LAEV-HUC-DIRECT-RESPONSE-1"
CA_CERT = "ca_certificate.pem"
CA_KEY = "ca_private_key.pem"
ISSUER_PUB = "issuer_public.pem"
ISSUER_KEY = "issuer_private.pem"
POLICY_FILE = "huc_policy.json"
ANCHOR_FILE = "trust_anchor.json"
LEDGER_FILE = "utxo_ledger.jsonl"
CERT_DIR = "certificates"
MAX_CERT_DAYS = 825
MAX_PACKAGE_BYTES = 10 * 1024 * 1024
MAX_CHALLENGE_TTL = 300
SAFE_INT = 9007199254740991


class HUCError(Exception):
    """Base error for HUC SDK operations."""


def _check_json(value: Any) -> None:
    if isinstance(value, float):
        raise ValueError("HUC canonical JSON does not allow floating-point values")
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) > SAFE_INT:
        raise ValueError("Integer outside the safe JSON range")
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str) or not k.isascii():
                raise ValueError("Protocol JSON object keys must be ASCII")
            _check_json(v)
    elif isinstance(value, list):
        for item in value:
            _check_json(item)


def canonical_json(value: Any) -> bytes:
    _check_json(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def strict_json_loads(raw: str) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError(f"Invalid JSON constant: {x}")))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def object_hash(value: Any) -> str:
    return sha256(canonical_json(value))


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_text(value: datetime | None = None) -> str:
    value = value or utc_now()
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception as exc:
        raise ValueError("Invalid UTC timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
        os.replace(tmp, path)
        try:
            os.chmod(path, mode)
        except OSError:
            pass
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def write_json(path: Path, obj: Any, mode: int = 0o600) -> None:
    atomic_write(path, json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False).encode() + b"\n", mode)


def read_json(path: Path) -> dict[str, Any]:
    value = strict_json_loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object at {path}")
    return value


def save_private(key: Any, path: Path) -> None:
    data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    atomic_write(path, data, 0o600)


def load_private(path: Path) -> Any:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def public_pem(key: Any) -> bytes:
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def public_der(key: Any) -> bytes:
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def cert_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def certificate_hash(cert: x509.Certificate) -> str:
    return sha256(cert_der(cert))


def certificate_bounds(cert: x509.Certificate) -> tuple[datetime, datetime]:
    before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    return before, after


def _sign_ed(key: ed25519.Ed25519PrivateKey, payload: dict[str, Any]) -> str:
    return base64.b64encode(key.sign(canonical_json(payload))).decode("ascii")


def _verify_ed(key: ed25519.Ed25519PublicKey, payload: dict[str, Any], signature: str) -> None:
    try:
        key.verify(base64.b64decode(signature, validate=True), canonical_json(payload))
    except (ValueError, InvalidSignature) as exc:
        raise ValueError("Invalid Ed25519 signature") from exc


def verify_ca(ca_cert: x509.Certificate) -> None:
    if ca_cert.subject != ca_cert.issuer or not isinstance(ca_cert.public_key(), rsa.RSAPublicKey):
        raise ValueError("Configured root CA must be a self-signed RSA certificate")
    try:
        ca_cert.public_key().verify(ca_cert.signature, ca_cert.tbs_certificate_bytes,
                                    padding.PKCS1v15(), ca_cert.signature_hash_algorithm)
    except InvalidSignature as exc:
        raise ValueError("Invalid self-signature on CA") from exc
    try:
        if not ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("Root CA BasicConstraints is not CA")
    except x509.ExtensionNotFound as exc:
        raise ValueError("Root CA missing BasicConstraints") from exc


def verify_leaf(cert: x509.Certificate, ca_cert: x509.Certificate) -> None:
    if cert.issuer != ca_cert.subject:
        raise ValueError("X.509 issuer does not match configured CA")
    try:
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("End-entity certificate cannot be a CA")
    except x509.ExtensionNotFound as exc:
        raise ValueError("X.509 certificate missing BasicConstraints") from exc
    if not isinstance(ca_cert.public_key(), rsa.RSAPublicKey):
        raise ValueError("Unsupported CA public key")
    try:
        ca_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                                    padding.PKCS1v15(), cert.signature_hash_algorithm)
    except InvalidSignature as exc:
        raise ValueError("Invalid X.509 signature") from exc


def _anchor_hash(anchor: dict[str, Any]) -> str:
    return object_hash(anchor)


def _policy_hash(policy: dict[str, Any]) -> str:
    return object_hash(policy)


def _safe_extract(bundle: bytes, dest: Path) -> None:
    import io
    with zipfile.ZipFile(io.BytesIO(bundle), "r") as zf:
        infos = zf.infolist()
        names = [i.filename for i in infos]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate ZIP entries are not allowed")
        if sum(i.file_size for i in infos) > MAX_PACKAGE_BYTES:
            raise ValueError("Credential package too large")
        for info in infos:
            target = (dest / info.filename).resolve()
            if dest.resolve() not in target.parents and target != dest.resolve():
                raise ValueError("Unsafe path in ZIP package")
        zf.extractall(dest)


@dataclass(frozen=True)
class IssuedCredential:
    certificate_pem: bytes
    certificate_sha256: str
    consensus_certificate: dict[str, Any]
    state_attestation: dict[str, Any]
    bundle: bytes
    trust_anchor_sha256: str


class HucIssuer:
    """Local issuer. Its private CA/issuer keys never leave its workspace."""

    def __init__(self, workspace: str | Path):
        self.workspace = Path(workspace).resolve()

    @classmethod
    def initialize(cls, workspace: str | Path, issuer_id: str = "LAEV-HUC-ISSUER",
                   state_ttl_seconds: int = 300) -> tuple["HucIssuer", str]:
        obj = cls(workspace)
        obj._initialize(issuer_id, state_ttl_seconds)
        trust = obj._load_trust()
        return obj, trust["anchor_sha256"]

    def _initialize(self, issuer_id: str, ttl: int) -> None:
        if not re.fullmatch(r"[A-Za-z0-9._-]{3,64}", issuer_id):
            raise ValueError("issuer_id must be 3-64 safe characters")
        if not 30 <= ttl <= 86400:
            raise ValueError("state_ttl_seconds must be 30-86400")
        self.workspace.mkdir(parents=True, exist_ok=True)
        protected = ["ca_private_key.pem", "ca_certificate.pem", "issuer_private.pem", "issuer_public.pem",
                     "huc_policy.json", "trust_anchor.json", "utxo_ledger.jsonl"]
        if any((self.workspace / name).exists() for name in protected):
            raise FileExistsError("Issuer workspace already initialized")
        now = utc_now().replace(tzinfo=None)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{issuer_id} Development CA")])
        ca_cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=3650))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                   .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                       key_encipherment=False, data_encipherment=False, key_agreement=False,
                       key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), critical=True)
                   .sign(ca_key, hashes.SHA256()))
        issuer_key = ed25519.Ed25519PrivateKey.generate()
        save_private(ca_key, self.workspace / "ca_private_key.pem")
        atomic_write(self.workspace / "ca_certificate.pem", ca_cert.public_bytes(serialization.Encoding.PEM), 0o644)
        save_private(issuer_key, self.workspace / "issuer_private.pem")
        atomic_write(self.workspace / "issuer_public.pem", public_pem(issuer_key.public_key()), 0o644)
        (self.workspace / CERT_DIR).mkdir(exist_ok=True)
        policy = {"schema": POLICY_SCHEMA, "protocol": f"LAEV-HUC-DIRECT/{SDK_VERSION}",
                  "issuer_id": issuer_id, "signature_algorithm": "Ed25519",
                  "consensus_mode": "ISSUER_SIGNED_POLICY", "required_signatures": 1,
                  "rules": {"x509_required": True, "huc_cc_required": True,
                            "state_attestation_required": True, "state_attestation_ttl_seconds": ttl,
                            "revoked_reactivation_allowed": False}}
        write_json(self.workspace / "huc_policy.json", policy, 0o644)
        atomic_write(self.workspace / "utxo_ledger.jsonl", b"", 0o600)
        anchor = {"schema": ANCHOR_SCHEMA, "version": SDK_VERSION, "issuer_id": issuer_id,
                  "created_at_utc": utc_text(), "ca_certificate_der_sha256": sha256(cert_der(ca_cert)),
                  "issuer_public_key_der_sha256": sha256(public_der(issuer_key.public_key())),
                  "policy_sha256": _policy_hash(policy)}
        write_json(self.workspace / "trust_anchor.json", anchor, 0o644)

    def _load_trust(self, expected_pin: str | None = None) -> dict[str, Any]:
        anchor = read_json(self.workspace / "trust_anchor.json")
        policy = read_json(self.workspace / "huc_policy.json")
        ca_cert = x509.load_pem_x509_certificate((self.workspace / "ca_certificate.pem").read_bytes())
        issuer_public = serialization.load_pem_public_key((self.workspace / "issuer_public.pem").read_bytes())
        if not isinstance(issuer_public, ed25519.Ed25519PublicKey):
            raise ValueError("Issuer key must be Ed25519")
        if anchor.get("schema") != ANCHOR_SCHEMA or policy.get("schema") != POLICY_SCHEMA:
            raise ValueError("Unknown trust anchor or policy")
        actual = _anchor_hash(anchor)
        if expected_pin and actual != expected_pin.strip().lower():
            raise ValueError("External trust anchor pin mismatch")
        if anchor.get("ca_certificate_der_sha256") != sha256(cert_der(ca_cert)):
            raise ValueError("CA certificate not pinned by anchor")
        if anchor.get("issuer_public_key_der_sha256") != sha256(public_der(issuer_public)):
            raise ValueError("Issuer public key not pinned by anchor")
        if anchor.get("policy_sha256") != _policy_hash(policy) or policy.get("issuer_id") != anchor.get("issuer_id"):
            raise ValueError("Issuer policy not pinned by anchor")
        verify_ca(ca_cert)
        return {"anchor": anchor, "anchor_sha256": actual, "policy": policy,
                "policy_sha256": _policy_hash(policy), "ca_cert": ca_cert,
                "issuer_public": issuer_public}

    def create_csr(self, common_name: str, output_dir: str | Path,
                   key_size: int = 2048) -> tuple[Path, Path]:
        if not common_name.strip() or key_size < 2048 or key_size > 4096:
            raise ValueError("Provide a subject name and RSA key size 2048-4096")
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", common_name.strip()).strip("._-") or "holder"
        stamp = utc_now().strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name.strip())])
        csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
        key_path = out / f"{safe}-{stamp}-private.pem"
        csr_path = out / f"{safe}-{stamp}.csr.pem"
        save_private(key, key_path)
        atomic_write(csr_path, csr.public_bytes(serialization.Encoding.PEM), 0o644)
        return csr_path, key_path

    def _validate_csr(self, csr_pem: bytes) -> x509.CertificateSigningRequest:
        csr = x509.load_pem_x509_csr(csr_pem)
        if not csr.is_signature_valid:
            raise ValueError("CSR proof-of-possession failed")
        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cn or not cn[0].value.strip():
            raise ValueError("CSR requires a non-empty Common Name")
        pub = csr.public_key()
        if not isinstance(pub, rsa.RSAPublicKey) or pub.key_size < 2048:
            raise ValueError("CSR requires RSA >= 2048 bits")
        if list(csr.extensions):
            raise ValueError("CSR extensions require an explicit issuance policy")
        return csr

    def _make_cert(self, csr: x509.CertificateSigningRequest, days: int) -> x509.Certificate:
        if not 1 <= days <= MAX_CERT_DAYS:
            raise ValueError(f"Certificate lifetime must be 1-{MAX_CERT_DAYS} days")
        ca_key = load_private(self.workspace / "ca_private_key.pem")
        ca_cert = x509.load_pem_x509_certificate((self.workspace / "ca_certificate.pem").read_bytes())
        now = utc_now().replace(tzinfo=None)
        return (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca_cert.subject)
                .public_key(csr.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=days))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True,
                    key_encipherment=True, data_encipherment=False, key_agreement=False,
                    key_cert_sign=False, crl_sign=False, encipher_only=None, decipher_only=None), critical=True)
                .sign(ca_key, hashes.SHA256()))

    def _ledger(self, trust: dict[str, Any]) -> dict[str, Any]:
        active: dict[str, dict[str, Any]] = {}
        statuses: dict[str, str] = {}
        previous = None
        events = []
        pub = trust["issuer_public"]
        path = self.workspace / LEDGER_FILE
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            try:
                event = strict_json_loads(line)
                payload = event["payload"]
                if payload.get("schema") != LEDGER_SCHEMA or payload.get("sequence") != len(events):
                    raise ValueError("Invalid ledger schema or sequence")
                if payload.get("previous_event_hash") != previous:
                    raise ValueError("Broken previous-event link")
                event_hash = object_hash(payload)
                if event.get("event_hash") != event_hash:
                    raise ValueError("Event hash mismatch")
                _verify_ed(pub, {"event_hash": event_hash}, event["signature"])
                action = payload["action"]
                digest = payload["certificate_sha256_der"]
                outpoint = payload.get("output")
                if action in {"ISSUE", "RENEW"}:
                    expected = {"txid": object_hash({k: v for k, v in payload.items() if k != "output"}), "vout": 0}
                    if outpoint != expected or digest in statuses:
                        raise ValueError("Invalid UTXO output or duplicate credential")
                    if action == "ISSUE":
                        if payload.get("previous_certificate_sha256_der") is not None or payload.get("previous_outpoint") is not None:
                            raise ValueError("ISSUE cannot consume previous output")
                    else:
                        old = payload.get("previous_certificate_sha256_der")
                        if old not in active or active[old] != payload.get("previous_outpoint"):
                            raise ValueError("RENEW does not consume exact active output")
                        statuses[old] = "SUPERSEDED"
                        del active[old]
                    active[digest] = outpoint
                    statuses[digest] = "ACTIVE"
                elif action == "REVOKE":
                    if digest not in active or active[digest] != payload.get("previous_outpoint"):
                        raise ValueError("REVOKE does not consume active output")
                    if outpoint is not None or not payload.get("reason"):
                        raise ValueError("Invalid REVOKE event")
                    statuses[digest] = "REVOKED"
                    del active[digest]
                else:
                    raise ValueError("Unknown ledger operation")
                previous = event_hash
                events.append(event)
            except Exception as exc:
                raise ValueError(f"Invalid UTXO ledger line {n}: {exc}") from exc
        return {"active": active, "statuses": statuses, "events": events,
                "event_count": len(events), "last_event_hash": previous}

    def _append_event(self, trust: dict[str, Any], action: str, digest: str,
                      previous_digest: str | None = None, previous_outpoint: dict[str, Any] | None = None,
                      reason: str | None = None) -> dict[str, Any]:
        try:
            with FileLock(str(self.workspace / (LEDGER_FILE + ".lock")), timeout=20):
                state = self._ledger(trust)
                if action == "ISSUE":
                    if digest in state["statuses"]:
                        raise ValueError("Certificate already recorded")
                elif action == "RENEW":
                    if not previous_digest or previous_digest not in state["active"] or state["active"][previous_digest] != previous_outpoint:
                        raise ValueError("Old UTXO is not active")
                    if digest in state["statuses"]:
                        raise ValueError("New certificate is already recorded")
                elif action == "REVOKE":
                    if digest not in state["active"] or state["active"][digest] != previous_outpoint:
                        raise ValueError("Certificate is not active")
                    if not reason:
                        raise ValueError("Revocation reason required")
                else:
                    raise ValueError("Unknown UTXO operation")
                payload = {"schema": LEDGER_SCHEMA, "sequence": state["event_count"],
                           "previous_event_hash": state["last_event_hash"], "action": action,
                           "certificate_sha256_der": digest,
                           "previous_certificate_sha256_der": previous_digest,
                           "previous_outpoint": previous_outpoint, "output": None,
                           "created_at_utc": utc_text(), "reason": reason}
                txid = object_hash({k: v for k, v in payload.items() if k != "output"})
                if action in {"ISSUE", "RENEW"}:
                    payload["output"] = {"txid": txid, "vout": 0}
                event_hash = object_hash(payload)
                event = {"payload": payload, "event_hash": event_hash,
                         "signature": _sign_ed(load_private(self.workspace / "issuer_private.pem"), {"event_hash": event_hash})}
                with (self.workspace / LEDGER_FILE).open("ab") as fh:
                    fh.write(canonical_json(event) + b"\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                self._ledger(trust)
                return event
        except Timeout as exc:
            raise TimeoutError("Could not lock issuer UTXO ledger") from exc

    def _cc_payload(self, trust: dict[str, Any], cert: x509.Certificate,
                    outpoint: dict[str, Any], sequence: int) -> dict[str, Any]:
        digest = certificate_hash(cert)
        return {"consensus_certificate_id": "huc-cc:" + object_hash({"certificate_sha256_der": digest,
                    "initial_utxo_outpoint": outpoint, "policy_sha256": trust["policy_sha256"]}),
                "certificate_sha256_der": digest, "certificate_serial_number": str(cert.serial_number),
                "initial_utxo_outpoint": outpoint, "utxo_sequence_at_issuance": sequence,
                "issuer_id": trust["policy"]["issuer_id"], "policy_sha256": trust["policy_sha256"],
                "consensus_mode": "ISSUER_SIGNED_POLICY", "required_signatures": 1,
                "operation": "ISSUE_OR_RENEW", "issued_at_utc": utc_text(),
                "not_after_utc": utc_text(certificate_bounds(cert)[1])}

    def _write_cc(self, trust: dict[str, Any], cert: x509.Certificate,
                  outpoint: dict[str, Any], sequence: int) -> Path:
        payload = self._cc_payload(trust, cert, outpoint, sequence)
        cc = {"type": CC_TYPE, "version": CC_VERSION, "payload": payload,
              "signature": _sign_ed(load_private(self.workspace / "issuer_private.pem"), payload)}
        path = self.workspace / CERT_DIR / f"consensus-{certificate_hash(cert)}.json"
        write_json(path, cc, 0o644)
        return path

    def _write_state(self, trust: dict[str, Any], cert: x509.Certificate, cc_path: Path) -> Path:
        state = self._ledger(trust)
        digest = certificate_hash(cert)
        issued_at = utc_now().replace(microsecond=0)
        expires_at = issued_at + timedelta(seconds=trust["policy"]["rules"]["state_attestation_ttl_seconds"])
        payload = {"schema": STATE_SCHEMA, "issuer_id": trust["policy"]["issuer_id"],
                   "certificate_sha256_der": digest,
                   "consensus_certificate_sha256": object_hash(read_json(cc_path)),
                   "status": state["statuses"].get(digest, "NOT_REGISTERED"),
                   "utxo_outpoint": state["active"].get(digest),
                   "ledger_sequence": state["event_count"] - 1,
                   "ledger_event_count": state["event_count"],
                   "ledger_head_hash": state["last_event_hash"],
                   "issued_at_utc": utc_text(issued_at),
                   "expires_at_utc": utc_text(expires_at)}
        att = {"payload": payload, "signature": _sign_ed(load_private(self.workspace / "issuer_private.pem"), payload)}
        path = self.workspace / CERT_DIR / f"state-{digest}.json"
        write_json(path, att, 0o644)
        return path

    def issue(self, csr_pem: bytes | str, days: int = 365) -> IssuedCredential:
        csr_raw = csr_pem.encode() if isinstance(csr_pem, str) else csr_pem
        csr = self._validate_csr(csr_raw)
        trust = self._load_trust()
        cert = self._make_cert(csr, days)
        digest = certificate_hash(cert)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        cert_path = self.workspace / CERT_DIR / f"certificate-{digest}.pem"
        atomic_write(cert_path, cert_pem, 0o644)
        event = self._append_event(trust, "ISSUE", digest)
        cc_path = self._write_cc(trust, cert, event["payload"]["output"], event["payload"]["sequence"])
        state_path = self._write_state(trust, cert, cc_path)
        bundle = self.create_bundle(cert_path)
        return IssuedCredential(cert_pem, digest, read_json(cc_path), read_json(state_path), bundle, trust["anchor_sha256"])

    def renew(self, old_certificate_pem: bytes, new_csr_pem: bytes, days: int = 365) -> IssuedCredential:
        old_cert = x509.load_pem_x509_certificate(old_certificate_pem)
        csr = self._validate_csr(new_csr_pem)
        if old_cert.subject != csr.subject:
            raise ValueError("Renewal CSR subject must match previous certificate")
        trust = self._load_trust()
        verify_leaf(old_cert, trust["ca_cert"])
        old_digest = certificate_hash(old_cert)
        state = self._ledger(trust)
        old_outpoint = state["active"].get(old_digest)
        if not old_outpoint:
            raise ValueError("Previous certificate has no active UTXO")
        cert = self._make_cert(csr, days)
        digest = certificate_hash(cert)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        cert_path = self.workspace / CERT_DIR / f"certificate-{digest}.pem"
        atomic_write(cert_path, cert_pem, 0o644)
        event = self._append_event(trust, "RENEW", digest, old_digest, old_outpoint)
        cc_path = self._write_cc(trust, cert, event["payload"]["output"], event["payload"]["sequence"])
        state_path = self._write_state(trust, cert, cc_path)
        old_cc = self.workspace / CERT_DIR / f"consensus-{old_digest}.json"
        self._write_state(trust, old_cert, old_cc)
        return IssuedCredential(cert_pem, digest, read_json(cc_path), read_json(state_path), self.create_bundle(cert_path), trust["anchor_sha256"])

    def revoke(self, certificate_pem: bytes, reason: str) -> dict[str, Any]:
        if not reason.strip():
            raise ValueError("Revocation reason required")
        cert = x509.load_pem_x509_certificate(certificate_pem)
        trust = self._load_trust()
        verify_leaf(cert, trust["ca_cert"])
        digest = certificate_hash(cert)
        state = self._ledger(trust)
        outpoint = state["active"].get(digest)
        if not outpoint:
            raise ValueError("Certificate is not active")
        self._append_event(trust, "REVOKE", digest, previous_outpoint=outpoint, reason=reason)
        cc_path = self.workspace / CERT_DIR / f"consensus-{digest}.json"
        att_path = self._write_state(trust, cert, cc_path)
        return {"status": "REVOKED", "certificate_sha256": digest,
                "state_attestation": read_json(att_path), "bundle": self.create_bundle_from_paths(cert, cc_path, att_path)}

    def refresh_state(self, certificate_pem: bytes) -> dict[str, Any]:
        cert = x509.load_pem_x509_certificate(certificate_pem)
        trust = self._load_trust()
        digest = certificate_hash(cert)
        cc_path = self.workspace / CERT_DIR / f"consensus-{digest}.json"
        if not cc_path.exists():
            raise FileNotFoundError("HUC-CC not found")
        state_path = self._write_state(trust, cert, cc_path)
        return read_json(state_path)

    def refresh_bundle(self, certificate_pem: bytes) -> tuple[dict[str, Any], bytes]:
        cert = x509.load_pem_x509_certificate(certificate_pem)
        trust = self._load_trust()
        verify_leaf(cert, trust["ca_cert"])
        digest = certificate_hash(cert)
        state = self._ledger(trust)
        if digest not in state["statuses"]:
            raise ValueError("Certificate is not registered in this issuer UTXO ledger")
        cc_path = self.workspace / CERT_DIR / f"consensus-{digest}.json"
        if not cc_path.exists():
            raise FileNotFoundError("HUC-CC not found")
        state_path = self._write_state(trust, cert, cc_path)
        attestation = read_json(state_path)
        bundle = self.create_bundle_from_paths(cert, cc_path, state_path)
        return attestation, bundle

    def create_bundle(self, certificate_path: str | Path) -> bytes:
        cert_pem = Path(certificate_path).read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)
        digest = certificate_hash(cert)
        cc_path = self.workspace / CERT_DIR / f"consensus-{digest}.json"
        if not cc_path.exists():
            raise FileNotFoundError("HUC-CC not found for certificate")
        state_path = self._write_state(self._load_trust(), cert, cc_path)
        return self.create_bundle_from_paths(cert, cc_path, state_path)

    def create_bundle_from_paths(self, cert: x509.Certificate, cc_path: Path, state_path: Path) -> bytes:
        trust = self._load_trust()
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        cc_raw = cc_path.read_bytes()
        state_raw = state_path.read_bytes()
        manifest = {"schema": PACKAGE_SCHEMA, "version": SDK_VERSION,
                    "certificate_sha256_der": certificate_hash(cert),
                    "consensus_certificate_sha256": object_hash(read_json(cc_path)),
                    "state_attestation_sha256": sha256(state_raw), "private_keys_included": False}
        import io
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("ca_certificate.pem", (self.workspace / "ca_certificate.pem").read_bytes())
            zf.writestr("issuer_public.pem", (self.workspace / "issuer_public.pem").read_bytes())
            zf.writestr("huc_policy.json", (self.workspace / "huc_policy.json").read_bytes())
            zf.writestr("trust_anchor.json", (self.workspace / "trust_anchor.json").read_bytes())
            zf.writestr("certificate.pem", cert_pem)
            zf.writestr("consensus_certificate.json", cc_raw)
            zf.writestr("state_attestation.json", state_raw)
            zf.writestr("package_manifest.json", json.dumps(manifest, indent=2) + "\n")
        return output.getvalue()


class HucVerifier:
    """Offline verifier and optional relying-party challenge service."""

    def __init__(self, trust_anchor_sha256: str, max_state_age_seconds: int = 300):
        if not re.fullmatch(r"[0-9a-fA-F]{64}", trust_anchor_sha256):
            raise ValueError("trust_anchor_sha256 must be a 64-character hex pin")
        if not 1 <= max_state_age_seconds <= 86400:
            raise ValueError("max_state_age_seconds must be 1-86400")
        self.pin = trust_anchor_sha256.lower()
        self.max_state_age_seconds = max_state_age_seconds

    def verify_bundle(self, bundle: bytes | str | Path) -> dict[str, Any]:
        raw = Path(bundle).read_bytes() if isinstance(bundle, (str, Path)) else bundle
        if len(raw) > MAX_PACKAGE_BYTES:
            raise ValueError("HUC credential package too large")
        with tempfile.TemporaryDirectory(prefix="huc-sdk-verify-") as td:
            root = Path(td)
            _safe_extract(raw, root)
            manifest = read_json(root / "package_manifest.json")
            allowed_entries = {"package_manifest.json", "ca_certificate.pem", "issuer_public.pem", "huc_policy.json",
                               "trust_anchor.json", "certificate.pem", "consensus_certificate.json", "state_attestation.json"}
            actual_entries = {p.name for p in root.iterdir() if p.is_file()}
            if actual_entries != allowed_entries:
                raise ValueError("Credential package contains missing or unexpected files")
            if (manifest.get("schema") != PACKAGE_SCHEMA or manifest.get("version") != SDK_VERSION
                    or manifest.get("private_keys_included") is not False):
                raise ValueError("Invalid HUC package manifest")
            cert_raw = (root / "certificate.pem").read_bytes()
            cc = read_json(root / "consensus_certificate.json")
            state = read_json(root / "state_attestation.json")
            if certificate_hash(x509.load_pem_x509_certificate(cert_raw)) != manifest.get("certificate_sha256_der"):
                raise ValueError("X.509 certificate hash mismatch")
            if object_hash(cc) != manifest.get("consensus_certificate_sha256"):
                raise ValueError("HUC-CC hash mismatch")
            if sha256((root / "state_attestation.json").read_bytes()) != manifest.get("state_attestation_sha256"):
                raise ValueError("State attestation hash mismatch")
            anchor = read_json(root / "trust_anchor.json")
            policy = read_json(root / "huc_policy.json")
            ca = x509.load_pem_x509_certificate((root / "ca_certificate.pem").read_bytes())
            issuer_pub = serialization.load_pem_public_key((root / "issuer_public.pem").read_bytes())
            if not isinstance(issuer_pub, ed25519.Ed25519PublicKey):
                raise ValueError("Issuer public key must be Ed25519")
            if _anchor_hash(anchor) != self.pin:
                raise ValueError("External trust anchor pin mismatch")
            verify_ca(ca)
            if anchor.get("schema") != ANCHOR_SCHEMA or policy.get("schema") != POLICY_SCHEMA:
                raise ValueError("Unknown HUC trust schema")
            if anchor.get("ca_certificate_der_sha256") != sha256(cert_der(ca)):
                raise ValueError("CA is not pinned by trust anchor")
            if anchor.get("issuer_public_key_der_sha256") != sha256(public_der(issuer_pub)):
                raise ValueError("Issuer public key is not pinned")
            if anchor.get("policy_sha256") != _policy_hash(policy) or policy.get("issuer_id") != anchor.get("issuer_id"):
                raise ValueError("Policy is not pinned by trust anchor")
            if policy.get("consensus_mode") != "ISSUER_SIGNED_POLICY" or policy.get("required_signatures") != 1:
                raise ValueError("Unsupported standalone HUC-CC mode")
            cert = x509.load_pem_x509_certificate(cert_raw)
            verify_leaf(cert, ca)
            cc_payload = cc.get("payload")
            if cc.get("type") != CC_TYPE or cc.get("version") != CC_VERSION or not isinstance(cc_payload, dict):
                raise ValueError("Unknown or malformed HUC-CC")
            digest = certificate_hash(cert)
            if cc_payload.get("certificate_sha256_der") != digest:
                raise ValueError("HUC-CC is not bound to this X.509 certificate")
            if cc_payload.get("policy_sha256") != _policy_hash(policy) or cc_payload.get("issuer_id") != policy.get("issuer_id"):
                raise ValueError("HUC-CC policy or issuer mismatch")
            outpoint = cc_payload.get("initial_utxo_outpoint")
            if (not isinstance(outpoint, dict)
                    or not isinstance(outpoint.get("txid"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", outpoint["txid"])
                    or outpoint.get("vout") != 0
                    or type(cc_payload.get("utxo_sequence_at_issuance")) is not int
                    or cc_payload.get("utxo_sequence_at_issuance", -1) < 0):
                raise ValueError("Invalid HUC-CC UTXO reference")
            expected_cc_id = "huc-cc:" + object_hash({"certificate_sha256_der": digest,
                "initial_utxo_outpoint": outpoint, "policy_sha256": _policy_hash(policy)})
            if cc_payload.get("consensus_certificate_id") != expected_cc_id or cc_payload.get("certificate_serial_number") != str(cert.serial_number):
                raise ValueError("HUC-CC identity or output reference mismatch")
            if (cc_payload.get("operation") != "ISSUE_OR_RENEW"
                    or cc_payload.get("consensus_mode") != "ISSUER_SIGNED_POLICY"
                    or type(cc_payload.get("required_signatures")) is not int
                    or cc_payload.get("required_signatures") != 1):
                raise ValueError("Invalid HUC-CC operation or signature policy")
            if parse_utc(cc_payload.get("not_after_utc", "")) != certificate_bounds(cert)[1]:
                raise ValueError("HUC-CC validity differs from X.509")
            _verify_ed(issuer_pub, cc_payload, cc.get("signature", ""))
            state_payload = state.get("payload")
            if not isinstance(state_payload, dict) or state_payload.get("schema") != STATE_SCHEMA:
                raise ValueError("Unknown state attestation")
            _verify_ed(issuer_pub, state_payload, state.get("signature", ""))
            if state_payload.get("certificate_sha256_der") != digest or state_payload.get("consensus_certificate_sha256") != object_hash(cc):
                raise ValueError("State attestation is not bound to X.509 and HUC-CC")
            if state_payload.get("issuer_id") != policy.get("issuer_id"):
                raise ValueError("State attestation issuer mismatch")
            if (type(state_payload.get("ledger_event_count")) is not int
                    or state_payload["ledger_event_count"] < 1
                    or type(state_payload.get("ledger_sequence")) is not int
                    or state_payload["ledger_sequence"] != state_payload["ledger_event_count"] - 1
                    or type(cc_payload.get("utxo_sequence_at_issuance")) is not int
                    or state_payload["ledger_sequence"] < cc_payload.get("utxo_sequence_at_issuance", 0)):
                raise ValueError("State attestation lacks a valid UTXO sequence")
            if not isinstance(state_payload.get("ledger_head_hash"), str) or not re.fullmatch(r"[0-9a-f]{64}", state_payload["ledger_head_hash"]):
                raise ValueError("Invalid ledger checkpoint in state attestation")
            if not isinstance(issuer_pub, ed25519.Ed25519PublicKey):
                raise ValueError("Unsupported issuer signature key")
            now = utc_now()
            cert_before, cert_after = certificate_bounds(cert)
            ca_before, ca_after = certificate_bounds(ca)
            if not ca_before <= now <= ca_after:
                raise ValueError("Root CA is outside validity")
            cert_time_valid = cert_before <= now <= cert_after
            state_issue = parse_utc(state_payload["issued_at_utc"])
            state_expiry = parse_utc(state_payload["expires_at_utc"])
            ttl = (state_expiry - state_issue).total_seconds()
            expected_ttl = policy["rules"]["state_attestation_ttl_seconds"]
            if not isinstance(expected_ttl, int) or not 30 <= expected_ttl <= 86400:
                raise ValueError("Invalid state TTL in issuer policy")
            if ttl != expected_ttl:
                raise ValueError("State attestation TTL conflicts with issuer policy")
            age = (now - state_issue).total_seconds()
            fresh = 0 <= age <= self.max_state_age_seconds and now <= state_expiry
            status = state_payload.get("status")
            if status == "ACTIVE":
                if state_payload.get("utxo_outpoint") != outpoint:
                    raise ValueError("ACTIVE UTXO does not match HUC-CC issuance output")
            elif status in {"SUPERSEDED", "REVOKED"}:
                if state_payload.get("utxo_outpoint") is not None:
                    raise ValueError("Consumed UTXO must not remain active")
            else:
                raise ValueError("Unknown certificate UTXO state")
            valid = bool(cert_time_valid and fresh and status == "ACTIVE")
            result = "VALID" if valid else ("INVALID" if not cert_time_valid or status in {"SUPERSEDED", "REVOKED"} else "INDETERMINATE")
            return {"result": result, "hybrid_valid": valid, "subject": cert.subject.rfc4514_string(),
                    "serial_number": str(cert.serial_number), "certificate_sha256": digest,
                    "consensus_certificate_sha256": object_hash(cc), "x509_signature_valid": True,
                    "huc_cc_signature_valid": True, "issuer_state_signature_valid": True,
                    "certificate_time_valid": cert_time_valid, "state_freshness_valid": fresh,
                    "state_age_seconds": max(0, int(age)), "utxo_status": status,
                    "utxo_outpoint": state_payload.get("utxo_outpoint"),
                    "ledger_sequence": state_payload.get("ledger_sequence"),
                    "ledger_head_hash": state_payload["ledger_head_hash"],
                    "trust_anchor_sha256": self.pin}

    def create_challenge(self, certificate_sha256: str, audience: str, ttl_seconds: int = 120) -> dict[str, Any]:
        if not re.fullmatch(r"[0-9a-f]{64}", certificate_sha256):
            raise ValueError("Invalid certificate SHA-256")
        if not audience.strip() or len(audience) > 256:
            raise ValueError("Audience is required and limited to 256 characters")
        if not 10 <= ttl_seconds <= MAX_CHALLENGE_TTL:
            raise ValueError("Challenge TTL must be 10-300 seconds")
        payload = {"schema": CHALLENGE_SCHEMA, "certificate_sha256_der": certificate_sha256,
                   "audience": audience.strip(), "nonce": secrets.token_hex(32),
                   "created_at_utc": utc_text(), "expires_at_utc": utc_text(utc_now() + timedelta(seconds=ttl_seconds))}
        return {"payload": payload, "challenge_id": object_hash(payload)}

    def verify_response(self, response: dict[str, Any], challenge: dict[str, Any],
                        expected_audience: str, replay_store: str | Path) -> dict[str, Any]:
        if response.get("schema") != RESPONSE_SCHEMA or response.get("challenge") != challenge:
            raise ValueError("Response is not bound to the issued challenge")
        payload = challenge.get("payload", {})
        if challenge.get("challenge_id") != object_hash(payload) or payload.get("schema") != CHALLENGE_SCHEMA:
            raise ValueError("Challenge integrity check failed")
        if payload.get("audience") != expected_audience:
            raise ValueError("Challenge audience mismatch")
        created, expires, now = parse_utc(payload["created_at_utc"]), parse_utc(payload["expires_at_utc"]), utc_now()
        nonce = payload.get("nonce")
        if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{64}", nonce):
            raise ValueError("Challenge nonce must be 256-bit lowercase hexadecimal")
        if expires <= created or expires - created > timedelta(seconds=MAX_CHALLENGE_TTL) or created > now + timedelta(minutes=2) or now > expires:
            raise ValueError("Challenge outside its validity window")
        responded_at = parse_utc(response.get("responded_at_utc", ""))
        if not created <= responded_at <= expires or responded_at > now + timedelta(minutes=2):
            raise ValueError("Response timestamp outside challenge validity")
        bundle = base64.b64decode(response["credential_bundle_b64"], validate=True)
        result = self.verify_bundle(bundle)
        if not result["hybrid_valid"] or result["certificate_sha256"] != payload["certificate_sha256_der"]:
            raise ValueError("Credential is not currently valid for this challenge")
        with tempfile.TemporaryDirectory(prefix="huc-direct-response-") as td:
            root = Path(td)
            _safe_extract(bundle, root)
            cert = x509.load_pem_x509_certificate((root / "certificate.pem").read_bytes())
            if not isinstance(cert.public_key(), rsa.RSAPublicKey):
                raise ValueError("Unsupported holder key algorithm")
            message = canonical_json({"domain": "LAEV-HUC-DIRECT-CHALLENGE/0.8", "challenge": payload})
            try:
                cert.public_key().verify(base64.b64decode(response["holder_signature_b64"], validate=True),
                                         message, padding.PKCS1v15(), hashes.SHA256())
            except InvalidSignature as exc:
                raise ValueError("Holder proof-of-possession is invalid") from exc
        store_path = Path(replay_store)
        store_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with FileLock(str(store_path) + ".lock", timeout=10):
                if utc_now() > expires:
                    raise ValueError("Challenge expired during verification")
                store = read_json(store_path) if store_path.exists() else {"schema": "LAEV-HUC-REPLAY-2", "nonces": {}}
                if store.get("schema") != "LAEV-HUC-REPLAY-2" or not isinstance(store.get("nonces"), dict):
                    raise ValueError("Replay store is invalid")
                nonce = payload["nonce"]
                active_nonces = {key: value for key, value in store["nonces"].items()
                                 if parse_utc(value) > now}
                if nonce in active_nonces:
                    raise ValueError("Challenge replay detected")
                if len(active_nonces) >= 100000:
                    raise ValueError("Replay store capacity reached; refusing verification")
                active_nonces[nonce] = utc_text(expires)
                write_json(store_path, {"schema": "LAEV-HUC-REPLAY-2", "nonces": active_nonces})
        except Timeout as exc:
            raise TimeoutError("Could not lock replay store") from exc
        return {"result": "VALID", "holder_proof_of_possession": True,
                "challenge_id": challenge["challenge_id"], "audience": expected_audience,
                "certificate_sha256": result["certificate_sha256"],
                "credential_status": result["utxo_status"], "state_freshness_valid": result["state_freshness_valid"]}


class HucPresenter:
    """Holder-side direct presentation. Private key never enters the credential ZIP."""

    @staticmethod
    def create_response(challenge: dict[str, Any], bundle: bytes | str | Path,
                        holder_private_key: str | Path) -> dict[str, Any]:
        payload = challenge.get("payload", {})
        if challenge.get("challenge_id") != object_hash(payload) or payload.get("schema") != CHALLENGE_SCHEMA:
            raise ValueError("Invalid challenge")
        now = utc_now()
        created, expires = parse_utc(payload["created_at_utc"]), parse_utc(payload["expires_at_utc"])
        if not isinstance(payload.get("nonce"), str) or not re.fullmatch(r"[0-9a-f]{64}", payload["nonce"]):
            raise ValueError("Challenge nonce must be 256-bit lowercase hexadecimal")
        if expires <= created or expires - created > timedelta(seconds=MAX_CHALLENGE_TTL) or created > now + timedelta(minutes=2) or now > expires:
            raise ValueError("Challenge expired or invalid")
        raw = Path(bundle).read_bytes() if isinstance(bundle, (str, Path)) else bundle
        if len(raw) > MAX_PACKAGE_BYTES:
            raise ValueError("Credential package too large")
        with tempfile.TemporaryDirectory(prefix="huc-holder-") as td:
            root = Path(td)
            _safe_extract(raw, root)
            cert = x509.load_pem_x509_certificate((root / "certificate.pem").read_bytes())
            if certificate_hash(cert) != payload.get("certificate_sha256_der"):
                raise ValueError("Challenge is for a different credential")
        key = load_private(Path(holder_private_key))
        if not isinstance(key, rsa.RSAPrivateKey) or public_der(key.public_key()) != public_der(cert.public_key()):
            raise ValueError("Holder private key does not match certificate")
        message = canonical_json({"domain": "LAEV-HUC-DIRECT-CHALLENGE/0.8", "challenge": payload})
        signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        return {"schema": RESPONSE_SCHEMA, "challenge": challenge,
                "credential_bundle_b64": base64.b64encode(raw).decode("ascii"),
                "holder_signature_b64": base64.b64encode(signature).decode("ascii"),
                "responded_at_utc": utc_text()}


def generate_csr(common_name: str, output_dir: str | Path, key_size: int = 2048) -> tuple[Path, Path]:
    """Generate a holder keypair and CSR locally; only the CSR goes to issuer."""
    if not common_name.strip() or not 2048 <= key_size <= 4096:
        raise ValueError("Provide a subject and RSA key size 2048-4096")
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", common_name.strip()).strip("._-") or "holder"
    stamp = utc_now().strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name.strip())])
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
    key_path, csr_path = out / f"{safe}-{stamp}-private.pem", out / f"{safe}-{stamp}.csr.pem"
    save_private(key, key_path)
    atomic_write(csr_path, csr.public_bytes(serialization.Encoding.PEM), 0o644)
    return csr_path, key_path
