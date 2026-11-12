# LAEV HUC 0.5.0 — Release Notes

## Main capability

The 0.5.0 release adds independent authority key custody and an offline signing round-trip. Three institutions can generate their own Ed25519 keypairs, publish only public descriptors, receive an enrollment package pinned to a trust anchor, approve a shared proposal on their own equipment, and return detached approval files.

The coordinator accepts only distinct authorized approvals that satisfy the policy threshold and refer to the still-current UTXO ledger checkpoint. Each authority has a durable local anti-equivocation lock per checkpoint and interactive confirmation is required by default. Successful finalization records the transition and produces/updates HUC-CC and HUC-UTXO evidence.

## New module

- `huc_federation.py`

## New commands

- `authority-init`
- `export-enrollment`
- `enroll`
- `export-state`
- `sync`
- `propose-issue`
- `propose-renew`
- `propose-revoke`
- `approve`
- `finalize`
- interactive `approve` review with an explicit `APROBAR` confirmation; `--yes` is reserved for controlled automation
- local anti-equivocation lock per checkpoint and process lock around approval/sync

## Verified limits

This release demonstrates separate authority key custody, 2-of-3 signature authorization, checkpoint-based stale proposal rejection and append-only state sync. It does not implement a distributed Byzantine fault-tolerant consensus algorithm. The coordinator continues to sequence and finalize the local ledger.
