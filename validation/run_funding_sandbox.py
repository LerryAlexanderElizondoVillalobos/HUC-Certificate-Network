"""Run a deterministic synthetic funding scenario and export JSON evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from validation.huc_funding_sandbox import FundingSandbox


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("funding-sandbox-evidence.json"))
    args = parser.parse_args()

    sandbox = FundingSandbox()
    intent = sandbox.create_intent(
        reference_id="HUC-PROJECT-DEMO-CONTRIBUTION-001",
        amount="42.50",
        currency="USD",
        idempotency_key="ci-intent-001",
        certificate_sha256="0" * 64,
    )
    sandbox.authorize(intent["intent_id"])
    sandbox.capture(intent["intent_id"])
    sandbox.refund(intent["intent_id"], amount="7.50", idempotency_key="ci-refund-001")
    final = sandbox.refund(intent["intent_id"], amount="35.00", idempotency_key="ci-refund-002")
    evidence = {
        "schema": "HUC-FUNDING-SANDBOX-RUN-1",
        "scenario": "synthetic_contribution_authorize_capture_partial_and_full_refund",
        "intent_id": intent["intent_id"],
        "final_status": final["status"],
        "evidence": sandbox.evidence(),
    }
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    evidence["report_sha256"] = hashlib.sha256(canonical).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "result": "synthetic_sandbox_scenario_completed",
        "output": str(args.output),
        "report_sha256": evidence["report_sha256"],
        "event_count": evidence["evidence"]["event_count"],
        "event_chain_valid": evidence["evidence"]["event_chain_valid"],
        "synthetic_balance": evidence["evidence"]["synthetic_balance"],
        "real_funds_moved": False,
    }, indent=2))
    return 0 if evidence["evidence"]["event_chain_valid"] and final["status"] == "refunded" else 1


if __name__ == "__main__":
    raise SystemExit(main())
