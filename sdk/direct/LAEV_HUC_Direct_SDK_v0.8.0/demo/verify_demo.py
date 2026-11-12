#!/usr/bin/env python3
"""Verify the public credential-state fixtures. Direct sample may have expired."""
from __future__ import annotations
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from huc_direct import HucVerifier

DEMO = ROOT / "demo" / "huc-direct-public"
PIN = (DEMO / "trust-anchor.sha256").read_text().strip()
verifier = HucVerifier(PIN, max_state_age_seconds=900)
results = {
    "active": verifier.verify_bundle(DEMO / "credential-active.zip"),
    "renewed": verifier.verify_bundle(DEMO / "credential-renewed-active.zip"),
    "superseded": verifier.verify_bundle(DEMO / "credential-superseded.zip"),
    "revoked": verifier.verify_bundle(DEMO / "credential-revoked.zip"),
}
assert results["active"]["utxo_status"] == "ACTIVE"
assert results["active"]["result"] in {"VALID", "INDETERMINATE"}
assert results["renewed"]["utxo_status"] == "ACTIVE"
assert results["renewed"]["result"] in {"VALID", "INDETERMINATE"}
assert results["superseded"]["utxo_status"] == "SUPERSEDED"
assert results["revoked"]["utxo_status"] == "REVOKED"
print(json.dumps({name: {"result": value["result"], "utxo_status": value["utxo_status"]}
                  for name, value in results.items()}, indent=2))
