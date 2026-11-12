#!/usr/bin/env python3
"""Build public-only fixtures proving the three-authority workflow.
All generated authority private keys remain in a temporary directory and are deleted.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import huc
import huc_federation as fed

OUT = ROOT / "demo" / "independent-authorities"


def copy_public(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="huc-federated-fixture-") as tmp:
        work = Path(tmp)
        coordinator = work / "coordinator"
        holder = work / "holder"
        auth_dirs = {
            "A": work / "device-A",
            "B": work / "device-B",
            "C": work / "device-C",
        }
        public_files = []
        for letter, aid in [("A", "INSTITUTION-A"), ("B", "INSTITUTION-B"), ("C", "INSTITUTION-C")]:
            result = fed.authority_init(aid, auth_dirs[letter])
            public_path = auth_dirs[letter] / fed.AUTHORITY_PUBLIC
            public_files.append(public_path)
            copy_public(public_path, OUT / "public" / f"authority-{letter}.json")

        init = huc.initialize(coordinator, threshold=2, authority_public_files=public_files)
        pin = init["trust_anchor_sha256"]
        (OUT / "trust-anchor.sha256").write_text(pin + "\n")

        for letter, aid in [("A", "INSTITUTION-A"), ("B", "INSTITUTION-B"), ("C", "INSTITUTION-C")]:
            package = work / f"enrollment-{letter}.zip"
            fed.export_enrollment(coordinator, aid, package, pin)
            fed.authority_enroll(auth_dirs[letter], package, pin)
            copy_public(package, OUT / "enrollment" / f"enrollment-{letter}.zip")

        req = huc.generate_request(holder, "LAEV Independent Authority Demonstration")
        csr_path = Path(req["csr_file"])
        issue_proposal = OUT / "proposals" / "issue-proposal.json"
        fed.prepare_issue(coordinator, csr_path, issue_proposal, days=365)

        issue_approvals = []
        for letter in ["A", "C"]:
            approval = OUT / "approvals" / f"issue-{letter}.json"
            fed.authority_approve(auth_dirs[letter], issue_proposal, approval)
            issue_approvals.append(approval)
        issue_result = fed.finalize_proposal(coordinator, issue_proposal, issue_approvals,
                                             work / "finalized", pin)
        cert_path = Path(issue_result["certificate_file"])
        active_bundle = OUT / "verification" / "active-certificate.zip"
        huc.export_bundle(coordinator, cert_path, active_bundle)
        active_result = huc.verify_bundle(active_bundle, pin)

        state_after_issue = OUT / "state-sync" / "after-issue.zip"
        fed.export_state(coordinator, state_after_issue, pin)
        for auth_dir in auth_dirs.values():
            fed.authority_sync(auth_dir, state_after_issue)

        revoke_proposal = OUT / "proposals" / "revoke-proposal.json"
        fed.prepare_revoke(coordinator, cert_path, "fixture-revocation", revoke_proposal)
        revoke_approvals = []
        for letter in ["B", "C"]:
            approval = OUT / "approvals" / f"revoke-{letter}.json"
            fed.authority_approve(auth_dirs[letter], revoke_proposal, approval)
            revoke_approvals.append(approval)
        fed.finalize_proposal(coordinator, revoke_proposal, revoke_approvals,
                              work / "finalized", pin)
        revoked_bundle = OUT / "verification" / "revoked-certificate.zip"
        huc.export_bundle(coordinator, cert_path, revoked_bundle)
        revoked_result = huc.verify_bundle(revoked_bundle, pin)

        state_after_revoke = OUT / "state-sync" / "after-revoke.zip"
        fed.export_state(coordinator, state_after_revoke, pin)

        # Export only public coordinator files: no CA key, ledger signing key, or authority private keys.
        public_workspace = OUT / "public-workspace"
        public_workspace.mkdir()
        for name in [huc.CA_CERT, huc.LEDGER_PUB, huc.POLICY_FILE, huc.ANCHOR_FILE, huc.LEDGER_FILE]:
            copy_public(coordinator / name, public_workspace / name)
        copy_public(cert_path, public_workspace / "certificate.pem")
        cc_path = coordinator / huc.CERT_DIR / f"consensus-{huc.cert_hash(huc.x509.load_pem_x509_certificate(cert_path.read_bytes()))}.json"
        copy_public(cc_path, public_workspace / "consensus_certificate.json")

        results = {
            "version": "0.5.0",
            "authority_count": 3,
            "threshold": "2-of-3",
            "authority_private_keys_in_coordinator": False,
            "authority_private_keys_in_release": False,
            "issue_signers": ["INSTITUTION-A", "INSTITUTION-C"],
            "revoke_signers": ["INSTITUTION-B", "INSTITUTION-C"],
            "active_bundle": {
                "package_verified": active_result["package_verified"],
                "hybrid_valid": active_result["hybrid_valid"],
                "utxo_status": active_result["utxo_status"],
                "result": active_result["result"],
            },
            "revoked_bundle": {
                "package_verified": revoked_result["package_verified"],
                "hybrid_valid": revoked_result["hybrid_valid"],
                "utxo_status": revoked_result["utxo_status"],
                "result": revoked_result["result"],
            },
            "expected": {
                "active_bundle_hybrid_valid": True,
                "revoked_bundle_hybrid_valid": False,
                "revoked_bundle_utxo_status": "REVOKED",
            },
        }
        (OUT / "verification-results.json").write_text(json.dumps(results, indent=2) + "\n")
        (OUT / "README.md").write_text(f'''# LAEV HUC 0.5 — demostración de autoridades independientes

Esta carpeta contiene evidencia pública de un flujo completo con tres autoridades cuyas claves privadas se generaron en tres directorios/dispositivos temporales distintos. Las claves privadas se eliminaron al terminar y no están incluidas en estos archivos.

**Huella SHA-256 del ancla:** `{pin}`

## Qué contiene

- `public/`: tres descriptores públicos independientes.
- `enrollment/`: paquetes de enrolamiento, sin claves privadas.
- `proposals/`: propuestas de emisión y revocación que se sometieron a firma.
- `approvals/`: aprobaciones firmadas desde tres almacenes privados separados (A+C para emitir, B+C para revocar).
- `state-sync/`: paquetes públicos de sincronización tras cada transición.
- `verification/active-certificate.zip`: certificado y evidencia válidos antes de revocar.
- `verification/revoked-certificate.zip`: mismo certificado con estado revocado.
- `public-workspace/`: archivos públicos del coordinador, sin claves privadas.
- `verification-results.json`: resultado esperado y observado.

## Comprobar los paquetes

Desde la raíz del proyecto:

```bash
PIN="$(cat demo/independent-authorities/trust-anchor.sha256)"
python huc.py verify-bundle --bundle demo/independent-authorities/verification/active-certificate.zip --trust-anchor-sha256 "$PIN"
python huc.py verify-bundle --bundle demo/independent-authorities/verification/revoked-certificate.zip --trust-anchor-sha256 "$PIN"
```

El paquete activo debe resultar `hybrid_valid: true`. El revocado debe quedar `package_verified: true`, pero `hybrid_valid: false` y `utxo_status: REVOKED`.

## Límite de la demostración

Los tres directorios simulan tres dispositivos independientes en una prueba reproducible. Para una prueba institucional real, cada entidad debe ejecutar `authority-init` en su propio dispositivo/servidor y transferir únicamente su descriptor público, propuestas, aprobaciones y paquetes públicos de estado. El coordinador todavía serializa el ledger; esto demuestra custodia independiente y quórum de autorización 2-de-3, no consenso BFT completo.
''')

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
