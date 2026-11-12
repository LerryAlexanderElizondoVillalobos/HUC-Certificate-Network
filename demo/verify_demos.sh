#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

verify_expected() {
  local label="$1" bundle="$2" pin_file="$3" expected="$4"
  local pin result_file
  pin="$(cat "$pin_file")"
  result_file="$(mktemp)"
  local status=0
  python huc.py verify-bundle --bundle "$bundle" --trust-anchor-sha256 "$pin" > "$result_file" || status=$?
  python - "$label" "$expected" "$status" "$result_file" <<'PY'
import json, sys
label, expected, exit_code, path = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
obj = json.load(open(path, encoding="utf-8"))
actual = obj.get("result")
expected_exit = 0 if expected == "VALID" else 1
print(f"{label}: result={actual}, utxo_status={obj.get('utxo_status')}, hybrid_valid={obj.get('hybrid_valid')}")
if actual != expected or exit_code != expected_exit:
    raise SystemExit(f"FAILED: se esperaba {expected} / exit {expected_exit}, se obtuvo {actual} / exit {exit_code}")
PY
  rm -f "$result_file"
}

verify_expected "ACTIVO" "demo/huc-demo-active.zip" "demo/huc-demo-active.sha256" "VALID"
verify_expected "RENOVADO ACTIVO" "demo/huc-demo-renewed-active.zip" "demo/huc-demo-renewed-active.sha256" "VALID"
verify_expected "ANTERIOR SUSTITUIDO" "demo/huc-demo-superseded.zip" "demo/huc-demo-superseded.sha256" "INVALID"
verify_expected "REVOCADO" "demo/huc-demo-revoked.zip" "demo/huc-demo-revoked.sha256" "INVALID"
echo "Todos los escenarios demo produjeron el resultado esperado."
