from __future__ import annotations
import argparse
import json
from pathlib import Path
from .core import HucIssuer, HucVerifier, HucPresenter, read_json


def main() -> int:
    p = argparse.ArgumentParser(description="LAEV HUC Direct SDK 0.8.0")
    sub = p.add_subparsers(dest="cmd", required=True)
    q = sub.add_parser("init"); q.add_argument("--workspace", type=Path, required=True); q.add_argument("--issuer-id", default="LAEV-HUC-ISSUER"); q.add_argument("--state-ttl", type=int, default=300)
    q = sub.add_parser("request"); q.add_argument("--name", required=True); q.add_argument("--out-dir", type=Path, required=True)
    q = sub.add_parser("issue"); q.add_argument("--workspace", type=Path, required=True); q.add_argument("--csr", type=Path, required=True); q.add_argument("--out", type=Path, required=True); q.add_argument("--days", type=int, default=365)
    q = sub.add_parser("renew"); q.add_argument("--workspace", type=Path, required=True); q.add_argument("--certificate", type=Path, required=True); q.add_argument("--csr", type=Path, required=True); q.add_argument("--out", type=Path, required=True); q.add_argument("--days", type=int, default=365)
    q = sub.add_parser("revoke"); q.add_argument("--workspace", type=Path, required=True); q.add_argument("--certificate", type=Path, required=True); q.add_argument("--reason", required=True); q.add_argument("--out", type=Path, required=True)
    q = sub.add_parser("refresh"); q.add_argument("--workspace", type=Path, required=True); q.add_argument("--certificate", type=Path, required=True); q.add_argument("--out", type=Path, required=True)
    q = sub.add_parser("verify"); q.add_argument("--bundle", type=Path, required=True); q.add_argument("--pin", required=True); q.add_argument("--max-state-age", type=int, default=300)
    q = sub.add_parser("challenge"); q.add_argument("--bundle", type=Path, required=True); q.add_argument("--pin", required=True); q.add_argument("--audience", required=True); q.add_argument("--out", type=Path, required=True)
    q = sub.add_parser("respond"); q.add_argument("--challenge", type=Path, required=True); q.add_argument("--bundle", type=Path, required=True); q.add_argument("--private-key", type=Path, required=True); q.add_argument("--out", type=Path, required=True)
    q = sub.add_parser("verify-response"); q.add_argument("--challenge", type=Path, required=True); q.add_argument("--response", type=Path, required=True); q.add_argument("--pin", required=True); q.add_argument("--audience", required=True); q.add_argument("--replay-store", type=Path, required=True)
    args = p.parse_args()
    try:
        if args.cmd == "init":
            issuer, pin = HucIssuer.initialize(args.workspace, args.issuer_id, args.state_ttl)
            result = {"trust_anchor_sha256": pin, "issuer_id": args.issuer_id}
        elif args.cmd == "request":
            # Generate the holder key locally and return only the public CSR to the issuer.
            from .core import generate_csr
            csr, key = generate_csr(args.name, args.out_dir)
            result = {"csr_file": str(csr), "private_key_file": str(key)}
        elif args.cmd == "issue":
            issuer = HucIssuer(args.workspace); issued = issuer.issue(args.csr.read_bytes(), args.days)
            args.out.parent.mkdir(parents=True, exist_ok=True); args.out.write_bytes(issued.bundle)
            result = {"bundle": str(args.out), "certificate_sha256": issued.certificate_sha256, "trust_anchor_sha256": issued.trust_anchor_sha256}
        elif args.cmd == "renew":
            issuer = HucIssuer(args.workspace); renewed = issuer.renew(args.certificate.read_bytes(), args.csr.read_bytes(), args.days)
            args.out.parent.mkdir(parents=True, exist_ok=True); args.out.write_bytes(renewed.bundle)
            result = {"bundle": str(args.out), "certificate_sha256": renewed.certificate_sha256}
        elif args.cmd == "revoke":
            result = HucIssuer(args.workspace).revoke(args.certificate.read_bytes(), args.reason)
            args.out.parent.mkdir(parents=True, exist_ok=True); args.out.write_bytes(result.pop("bundle"))
            result["bundle"] = str(args.out)
        elif args.cmd == "refresh":
            issuer = HucIssuer(args.workspace); attestation, bundle = issuer.refresh_bundle(args.certificate.read_bytes())
            args.out.parent.mkdir(parents=True, exist_ok=True); args.out.write_bytes(bundle)
            result = {"status": attestation["payload"]["status"], "bundle": str(args.out)}
        elif args.cmd == "verify":
            issuer_verifier = HucVerifier(args.pin, args.max_state_age); result = issuer_verifier.verify_bundle(args.bundle)
        elif args.cmd == "challenge":
            from cryptography import x509
            from .core import _safe_extract, certificate_hash
            import tempfile
            with tempfile.TemporaryDirectory() as td:
                root = Path(td); _safe_extract(args.bundle.read_bytes(), root)
                cert = x509.load_pem_x509_certificate((root / "certificate.pem").read_bytes())
                verifier = HucVerifier(args.pin)
                verification = verifier.verify_bundle(args.bundle)
                if not verification["hybrid_valid"]:
                    raise ValueError(f"Cannot challenge a non-valid credential: {verification['result']}")
                challenge = verifier.create_challenge(certificate_hash(cert), args.audience)
            args.out.parent.mkdir(parents=True, exist_ok=True); args.out.write_text(json.dumps(challenge, indent=2))
            result = {"challenge_file": str(args.out), "challenge_id": challenge["challenge_id"]}
        elif args.cmd == "respond":
            challenge = read_json(args.challenge); response = HucPresenter.create_response(challenge, args.bundle, args.private_key)
            args.out.parent.mkdir(parents=True, exist_ok=True); args.out.write_text(json.dumps(response, indent=2))
            result = {"response_file": str(args.out)}
        elif args.cmd == "verify-response":
            challenge = read_json(args.challenge); response = read_json(args.response)
            verifier = HucVerifier(args.pin)
            result = verifier.verify_response(response, challenge, args.audience, args.replay_store)
        else:
            raise ValueError("Unknown command")
        print(json.dumps(result, indent=2, default=str))
        return 0
    except Exception as exc:
        print(json.dumps({"error": str(exc)}), flush=True)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
