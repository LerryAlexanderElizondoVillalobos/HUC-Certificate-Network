#!/usr/bin/env python3
"""Run the optional private HUC issuer API. Put behind a TLS reverse proxy."""
import os
from pathlib import Path
import uvicorn
from huc_direct import HucIssuer
from huc_direct.service import create_app

workspace = Path(os.environ.get("HUC_ISSUER_WORKSPACE", "./issuer-workspace"))
admin_token = os.environ.get("HUC_ADMIN_TOKEN", "")
if not workspace.exists() or not (workspace / "trust_anchor.json").exists():
    raise SystemExit("Issuer workspace is missing; initialize it before starting the API.")
if len(admin_token) < 32:
    raise SystemExit("Set HUC_ADMIN_TOKEN to a random secret of at least 32 characters.")
app = create_app(HucIssuer(workspace), admin_token, os.environ.get("HUC_REPLAY_STORE", "./replay-store.json"))
uvicorn.run(app, host=os.environ.get("HUC_API_HOST", "127.0.0.1"),
            port=int(os.environ.get("HUC_API_PORT", "8088")), log_level="info")
