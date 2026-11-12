"""Optional FastAPI adapter for enterprise and educational platforms.

The issuer key store stays local to this service. Deploy behind HTTPS/mTLS,
network controls, rate limiting and a secret manager. This adapter is a sample,
not a hardened internet-facing PKI service.
"""
from __future__ import annotations

import base64
import hmac
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from .core import HucIssuer, HucVerifier


class IssueRequest(BaseModel):
    csr_pem: str = Field(min_length=100, max_length=200_000)
    days: int = Field(default=365, ge=1, le=825)


class RenewRequest(BaseModel):
    previous_certificate_pem: str = Field(min_length=100, max_length=200_000)
    new_csr_pem: str = Field(min_length=100, max_length=200_000)
    days: int = Field(default=365, ge=1, le=825)


class RefreshRequest(BaseModel):
    certificate_pem: str = Field(min_length=100, max_length=200_000)


class RevokeRequest(BaseModel):
    certificate_pem: str = Field(min_length=100, max_length=200_000)
    reason: str = Field(min_length=3, max_length=500)


class VerifyRequest(BaseModel):
    bundle_b64: str = Field(min_length=20, max_length=15_000_000)


class ChallengeRequest(BaseModel):
    certificate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    audience: str = Field(min_length=1, max_length=256)
    ttl_seconds: int = Field(default=120, ge=10, le=300)


class DirectVerifyRequest(BaseModel):
    challenge: dict[str, Any]
    response: dict[str, Any]
    audience: str = Field(min_length=1, max_length=256)


def create_app(issuer: HucIssuer, admin_token: str, replay_store: str | Path,
               max_state_age_seconds: int = 300) -> FastAPI:
    if len(admin_token) < 32:
        raise ValueError("admin_token must be at least 32 characters of high-entropy material")
    trust = issuer._load_trust()
    verifier = HucVerifier(trust["anchor_sha256"], max_state_age_seconds)
    app = FastAPI(title="LAEV HUC Direct API", version="0.8.0",
                  description="Issue, present and verify HUC credentials without node networks.")

    def require_admin(value: str | None) -> None:
        if not hmac.compare_digest(value or "", admin_token):
            raise HTTPException(status_code=401, detail="Unauthorized issuer operation")

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "service": "huc-direct", "version": "0.8.0"}

    @app.get("/v1/trust")
    def trust_info():
        return {"issuer_id": trust["policy"]["issuer_id"],
                "trust_anchor_sha256": trust["anchor_sha256"],
                "policy_sha256": trust["policy_sha256"],
                "state_ttl_seconds": trust["policy"]["rules"]["state_attestation_ttl_seconds"]}

    @app.post("/v1/credentials/issue")
    def issue(body: IssueRequest, x_huc_admin_token: str | None = Header(default=None)):
        require_admin(x_huc_admin_token)
        try:
            issued = issuer.issue(body.csr_pem, body.days)
            return {"certificate_pem": issued.certificate_pem.decode("ascii"),
                    "certificate_sha256": issued.certificate_sha256,
                    "consensus_certificate": issued.consensus_certificate,
                    "state_attestation": issued.state_attestation,
                    "credential_bundle_b64": base64.b64encode(issued.bundle).decode("ascii"),
                    "trust_anchor_sha256": issued.trust_anchor_sha256}
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/v1/credentials/renew")
    def renew(body: RenewRequest, x_huc_admin_token: str | None = Header(default=None)):
        require_admin(x_huc_admin_token)
        try:
            renewed = issuer.renew(body.previous_certificate_pem.encode("ascii"),
                                   body.new_csr_pem.encode("ascii"), body.days)
            return {"certificate_pem": renewed.certificate_pem.decode("ascii"),
                    "certificate_sha256": renewed.certificate_sha256,
                    "consensus_certificate": renewed.consensus_certificate,
                    "state_attestation": renewed.state_attestation,
                    "credential_bundle_b64": base64.b64encode(renewed.bundle).decode("ascii"),
                    "trust_anchor_sha256": renewed.trust_anchor_sha256}
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/v1/credentials/refresh")
    def refresh(body: RefreshRequest, x_huc_admin_token: str | None = Header(default=None)):
        require_admin(x_huc_admin_token)
        try:
            attestation, bundle = issuer.refresh_bundle(body.certificate_pem.encode("ascii"))
            return {"status": attestation["payload"]["status"],
                    "state_attestation": attestation,
                    "credential_bundle_b64": base64.b64encode(bundle).decode("ascii")}
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/v1/credentials/revoke")
    def revoke(body: RevokeRequest, x_huc_admin_token: str | None = Header(default=None)):
        require_admin(x_huc_admin_token)
        try:
            result = issuer.revoke(body.certificate_pem.encode("ascii"), body.reason)
            return {"status": result["status"], "certificate_sha256": result["certificate_sha256"],
                    "state_attestation": result["state_attestation"],
                    "credential_bundle_b64": base64.b64encode(result["bundle"]).decode("ascii")}
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/v1/credentials/verify")
    def verify(body: VerifyRequest):
        try:
            raw = base64.b64decode(body.bundle_b64, validate=True)
            return verifier.verify_bundle(raw)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/v1/direct/challenges")
    def challenge(body: ChallengeRequest):
        try:
            return verifier.create_challenge(body.certificate_sha256, body.audience, body.ttl_seconds)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/v1/direct/verify")
    def verify_direct(body: DirectVerifyRequest):
        try:
            return verifier.verify_response(body.response, body.challenge, body.audience, replay_store)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    return app
