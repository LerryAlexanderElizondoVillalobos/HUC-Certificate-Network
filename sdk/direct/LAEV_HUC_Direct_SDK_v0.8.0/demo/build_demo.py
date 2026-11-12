#!/usr/bin/env python3
"""Build public HUC Direct SDK fixtures. All private keys stay in a temp dir."""
from __future__ import annotations
import json
import shutil
import sys
import tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from huc_direct import HucIssuer, HucPresenter, HucVerifier, generate_csr

OUT = ROOT / "demo" / "huc-direct-public"


def _write_cert(temp: Path, name: str, pem: bytes) -> Path:
    path = temp / name
    path.write_bytes(pem)
    return path


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="huc-direct-sdk-demo-") as td:
        temp = Path(td)
        issuer, pin = HucIssuer.initialize(temp / "issuer", "LAEV-DIRECT-DEMO", 900)
        verifier = HucVerifier(pin, max_state_age_seconds=900)
        csr1, key1 = generate_csr("LAEV HUC Direct SDK Demo Holder", temp / "holder-1")
        issue = issuer.issue(csr1.read_bytes(), days=365)
        active_bundle = issue.bundle
        (OUT / "credential-active.zip").write_bytes(active_bundle)
        active_result = verifier.verify_bundle(active_bundle)

        challenge = verifier.create_challenge(issue.certificate_sha256, "demo.education.example", 300)
        response = HucPresenter.create_response(challenge, active_bundle, key1)
        (OUT / "direct-challenge.json").write_text(json.dumps(challenge, indent=2) + "\n")
        (OUT / "direct-response.json").write_text(json.dumps(response, indent=2) + "\n")
        direct_result = verifier.verify_response(response, challenge, "demo.education.example", temp / "replay.json")

        csr2, _key2 = generate_csr("LAEV HUC Direct SDK Demo Holder", temp / "holder-2")
        renewed = issuer.renew(issue.certificate_pem, csr2.read_bytes(), days=365)
        (OUT / "credential-renewed-active.zip").write_bytes(renewed.bundle)
        old_path = _write_cert(temp, "old-certificate.pem", issue.certificate_pem)
        old_bundle = issuer.create_bundle(old_path)
        (OUT / "credential-superseded.zip").write_bytes(old_bundle)
        renewed_result = verifier.verify_bundle(renewed.bundle)
        superseded_result = verifier.verify_bundle(old_bundle)

        revoked = issuer.revoke(renewed.certificate_pem, "demo-revocation")
        (OUT / "credential-revoked.zip").write_bytes(revoked["bundle"])
        revoked_result = verifier.verify_bundle(revoked["bundle"])

        public = OUT / "public-metadata"
        public.mkdir()
        for name in ["ca_certificate.pem", "issuer_public.pem", "huc_policy.json", "trust_anchor.json"]:
            shutil.copy2(issuer.workspace / name, public / name)
        shutil.copy2(old_path, public / "certificate-issued.pem")
        shutil.copy2(issuer.workspace / "certificates" / f"consensus-{issue.certificate_sha256}.json", public / "huc-cc-issued.json")
        shutil.copy2(_write_cert(temp, "new-certificate.pem", renewed.certificate_pem), public / "certificate-renewed.pem")
        shutil.copy2(issuer.workspace / "certificates" / f"consensus-{renewed.certificate_sha256}.json", public / "huc-cc-renewed.json")
        (OUT / "trust-anchor.sha256").write_text(pin + "\n")
        results = {
            "sdk_version": "0.8.0",
            "nodes_required": False,
            "blockchain_required": False,
            "optional_direct_exchange": True,
            "trust_anchor_sha256": pin,
            "issuance": {"result": active_result["result"], "status": active_result["utxo_status"]},
            "direct_exchange": {"result": direct_result["result"], "holder_proof_of_possession": direct_result["holder_proof_of_possession"]},
            "renewal": {"new_result": renewed_result["result"], "old_result": superseded_result["result"], "old_status": superseded_result["utxo_status"]},
            "revocation": {"result": revoked_result["result"], "status": revoked_result["utxo_status"]},
            "checks": {
                "offline_active_package_valid": active_result["hybrid_valid"],
                "direct_holder_proof_valid": direct_result["holder_proof_of_possession"],
                "renewed_package_valid": renewed_result["hybrid_valid"],
                "old_package_superseded": superseded_result["utxo_status"] == "SUPERSEDED",
                "revoked_package_invalid": revoked_result["utxo_status"] == "REVOKED" and not revoked_result["hybrid_valid"],
                "private_keys_excluded_from_demo": True,
            },
            "note": "Direct challenge/response is a time-limited sample. It expires after 300 seconds; use fresh challenges for actual testing.",
        }
        (OUT / "demo-results.json").write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n")
        (OUT / "README.md").write_text("""# HUC Direct SDK 0.8 public demo

- `credential-active.zip`: active X.509 + HUC-CC + UTXO state.
- `credential-renewed-active.zip`: the renewed credential.
- `credential-superseded.zip`: the predecessor after renewal.
- `credential-revoked.zip`: the renewed credential after revocation.
- `direct-challenge.json` and `direct-response.json`: sample of the optional holder challenge exchange. The challenge expires after five minutes; use fresh challenges for actual testing.
- `public-metadata/`: public CA, public issuer key, policy, trust anchor and public certificate evidence.
- `trust-anchor.sha256`: out-of-band trust pin for this demo only.

No private keys are included. The private keys used to generate these files were created in a temporary workspace and removed after generation.
""", encoding="utf-8")
        if not all(results["checks"].values()):
            raise SystemExit("Demo assertion failed")
        print(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
