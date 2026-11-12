"""Illustrative HR/ERP integration using the Python SDK."""
from pathlib import Path
from huc_direct import HucVerifier

TRUST_PIN = "REPLACE_WITH_PIN_DISTRIBUTED_OUT_OF_BAND"


def verify_employee_training_credential(bundle_zip: bytes, employee_id: str) -> dict:
    verifier = HucVerifier(TRUST_PIN, max_state_age_seconds=300)
    result = verifier.verify_bundle(bundle_zip)
    if result["result"] != "VALID":
        raise PermissionError(f"Credential rejected for employee {employee_id}: {result['result']}")
    # Bind the verified subject/hash to the company's HR record after identity proofing.
    return {"employee_id": employee_id, "credential_subject": result["subject"],
            "credential_sha256": result["certificate_sha256"], "status": result["utxo_status"]}
