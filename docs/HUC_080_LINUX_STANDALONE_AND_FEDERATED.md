# HUC 0.8.0 — Linux standalone and federated operating modes

## Architectural decision

HUC must be usable immediately on one Linux host without waiting for a node network. The same release also supports a later four-node institutional deployment. These are two operating modes of one authorization model, not two incompatible products.

## Mode A — STANDALONE (default; no nodes)

- One Linux service owns one durable SQLite registry.
- SQLite WAL, a unique UTXO outpoint and `BEGIN IMMEDIATE` serialize competing consumes.
- Four institutional clients may connect to this single service; they do not each maintain an independent authoritative spend database.
- It runs with no node keys, peer map, network manifest, quorum or node process.
- It guarantees one successful consume within that single authoritative database.
- Backups, access control, host hardening and disaster recovery remain operational requirements.

Example:
```python
from huc_x509_external import SingleUseUTXORegistry, load_cert
registry = SingleUseUTXORegistry("/var/lib/huc/utxo.sqlite3")
certificate = load_cert("/etc/huc/certificates/test-holder.pem")
# Verify authorization and consume using registry.consume(authorization, certificate)
```

Do not place separate SQLite copies at four institutions and call that global single-use: isolated databases cannot know that another institution has consumed the same outpoint.

## Mode B — FEDERATED (enable when nodes are ready)

- Uses the existing HUC replicated-state/BFT components (`huc_replicated.py`, `huc_bft.py`, `huc_peer.py`, `huc_bft_peer.py`).
- The existing four-validator profile uses n=4, f=1 and quorum=3.
- Each institution operates its own Linux node and retains its own node private key.
- A transition is accepted only with a valid quorum commit; nodes verify and persist the same committed state.
- Network manifests, node trust pins, TLS peer map and node processes are required only in this mode.
- The current BFT implementation and its documented recovery/view-change limitations must be reviewed before production. A network of four is not production-ready merely because four processes run in CI.

The node mode must fail closed if the configured quorum is unavailable. It must never silently fall back to a local database, because that could authorize a second spend.

## Mode selection and migration

1. Install and operate standalone mode first.
2. Keep a stable API and identical authorization/outpoint format in both modes.
3. To migrate: stop new spends; take a consistent SQLite snapshot; verify every event and consumed outpoint; generate a signed migration manifest with database hash, chain head, count and timestamp; import and independently verify it on all four nodes; obtain explicit quorum acceptance; only then switch the service to FEDERATED.
4. Do not allow standalone and federated authorities to spend concurrently during cutover.
5. Preserve the standalone snapshot as read-only audit evidence. Rollback requires a controlled checkpoint/epoch decision; never restore an older spend database and resume spending.

## Four-institution pilot

Run four institutional clients against one standalone Linux service first. Test distinct X.509 chains, signature validation, expired/revoked certificates, simultaneous attempts from all four clients, restart/recovery and audit exports. Then repeat the same scenarios against four BFT nodes and verify all committed state heads match.

## Security boundaries

The current X.509 adapter reports revocation as NOT_CHECKED and is not a complete RFC 5280 validator. CRL/OCSP and full path/policy validation are required before live institutional certificates are accepted. Use only explicitly authorized test certificates during the pilot. Never export or commit private keys, PINs or real personal certificate data.
