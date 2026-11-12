#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cd "$ROOT"
mkdir -p "$TMP/public" "$TMP/authority-a" "$TMP/authority-b" "$TMP/authority-c" "$TMP/workspace" "$TMP/handoff" "$TMP/approvals" "$TMP/proposals" "$TMP/finalized" "$TMP/holder"
python huc_federation.py authority-init --id INSTITUTION-A --out-dir "$TMP/authority-a"
python huc_federation.py authority-init --id INSTITUTION-B --out-dir "$TMP/authority-b"
python huc_federation.py authority-init --id INSTITUTION-C --out-dir "$TMP/authority-c"
cp "$TMP/authority-a/authority-public.json" "$TMP/public/A.json"
cp "$TMP/authority-b/authority-public.json" "$TMP/public/B.json"
cp "$TMP/authority-c/authority-public.json" "$TMP/public/C.json"
python huc.py init --workspace "$TMP/workspace" --threshold 2 \
  --authority-public "$TMP/public/A.json" "$TMP/public/B.json" "$TMP/public/C.json" > "$TMP/init.json"
PIN="$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["trust_anchor_sha256"])' "$TMP/init.json")"
for ID in A B C; do
  case "$ID" in A) ADIR="$TMP/authority-a";; B) ADIR="$TMP/authority-b";; C) ADIR="$TMP/authority-c";; esac
  python huc_federation.py export-enrollment --workspace "$TMP/workspace" --authority-id "INSTITUTION-$ID" --output "$TMP/handoff/enroll-$ID.zip" --trust-anchor-sha256 "$PIN" >/dev/null
  python huc_federation.py enroll --authority-dir "$ADIR" --package "$TMP/handoff/enroll-$ID.zip" --trust-anchor-sha256 "$PIN" >/dev/null
done
python huc.py request --out-dir "$TMP/holder" --name "Independent Authority Demo" > "$TMP/request.json"
CSR="$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["csr_file"])' "$TMP/request.json")"
python huc_federation.py propose-issue --workspace "$TMP/workspace" --csr "$CSR" --output "$TMP/proposals/issue.json" >/dev/null
python huc_federation.py approve --authority-dir "$TMP/authority-a" --proposal "$TMP/proposals/issue.json" --output "$TMP/approvals/issue-A.json" --yes >/dev/null
python huc_federation.py approve --authority-dir "$TMP/authority-c" --proposal "$TMP/proposals/issue.json" --output "$TMP/approvals/issue-C.json" --yes >/dev/null
python huc_federation.py finalize --workspace "$TMP/workspace" --proposal "$TMP/proposals/issue.json" --approval "$TMP/approvals/issue-A.json" --approval "$TMP/approvals/issue-C.json" --trust-anchor-sha256 "$PIN" --output-dir "$TMP/finalized" > "$TMP/issue-final.json"
CERT="$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["certificate_file"])' "$TMP/issue-final.json")"
python huc.py verify --workspace "$TMP/workspace" --certificate "$CERT" --trust-anchor-sha256 "$PIN" > "$TMP/verify-active.json"
python huc_federation.py export-state --workspace "$TMP/workspace" --output "$TMP/handoff/state-after-issue.zip" --trust-anchor-sha256 "$PIN" >/dev/null
for ADIR in "$TMP/authority-a" "$TMP/authority-b" "$TMP/authority-c"; do
  python huc_federation.py sync --authority-dir "$ADIR" --package "$TMP/handoff/state-after-issue.zip" >/dev/null
done
python huc_federation.py propose-revoke --workspace "$TMP/workspace" --certificate "$CERT" --reason "demo-revocation" --output "$TMP/proposals/revoke.json" >/dev/null
python huc_federation.py approve --authority-dir "$TMP/authority-b" --proposal "$TMP/proposals/revoke.json" --output "$TMP/approvals/revoke-B.json" --yes >/dev/null
python huc_federation.py approve --authority-dir "$TMP/authority-c" --proposal "$TMP/proposals/revoke.json" --output "$TMP/approvals/revoke-C.json" --yes >/dev/null
python huc_federation.py finalize --workspace "$TMP/workspace" --proposal "$TMP/proposals/revoke.json" --approval "$TMP/approvals/revoke-B.json" --approval "$TMP/approvals/revoke-C.json" --trust-anchor-sha256 "$PIN" --output-dir "$TMP/finalized" > "$TMP/revoke-final.json"
python huc.py verify --workspace "$TMP/workspace" --certificate "$CERT" --trust-anchor-sha256 "$PIN" > "$TMP/verify-revoked.json" || true
python - <<'PY' "$TMP/verify-active.json" "$TMP/verify-revoked.json"
import json,sys
active=json.load(open(sys.argv[1])); revoked=json.load(open(sys.argv[2]))
assert active["hybrid_valid"] is True
assert revoked["hybrid_valid"] is False and revoked["utxo_status"] == "REVOKED"
print("PASS: three independent authority keys approved 2-of-3 ISSUE and REVOKE.")
print("PASS: active certificate verified; revoked certificate rejected.")
PY
