"""Illustrative school/university credential verification."""
from huc_direct import HucVerifier

TRUST_PIN = "REPLACE_WITH_ISSUER_PIN_FROM_TRUSTED_REGISTRY"


def verify_diploma(diploma_package: bytes, expected_student_cn: str) -> dict:
    result = HucVerifier(TRUST_PIN, max_state_age_seconds=300).verify_bundle(diploma_package)
    if result["result"] != "VALID":
        raise ValueError(f"Diploma is not currently valid: {result['result']}")
    if result["subject"] != f"CN={expected_student_cn}":
        raise ValueError("Credential subject does not match the verified student record")
    return {"student": expected_student_cn, "serial": result["serial_number"],
            "issuer": result["issuer_id"], "verified": True}
