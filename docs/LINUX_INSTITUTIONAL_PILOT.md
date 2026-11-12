# HUC Linux — Institutional Pilot Plan (4 organizations)

## Purpose and status

Linux is the first reference deployment target. This runbook defines a controlled pilot with four independently administered organizations. It is not a production approval or a claim that external institutions have already participated.

The automated test `tests/test_four_institution_pilot.py` is a four-authority rehearsal: four distinct signing identities, isolated directories, independent approvals, public-only enrollment, state synchronization and the ISSUE → RENEW → REVOKE lifecycle. It runs on one CI host. It does not prove four physical institutions or four-host BFT interoperability.

## Two independent quorum mechanisms

Do not conflate these roles:

1. **HUC-CC institutional approval:** four independent authority keys with threshold 3-of-4 authorize certificate lifecycle proposals in the federation workflow.
2. **HUC BFT replicated validators:** four independently operated validator nodes with f=1 and quorum 3-of-4 agree on replicated state transitions.

An organization may operate both roles, but the authority signing key and validator key must be different keys with separate access controls and audit trails. An authority approval is not a BFT vote.

## Target topology

| Participant | Responsibility | Minimum deployment |
|---|---|---|
| Institution A | Authority + validator | One independently administered Linux host |
| Institution B | Authority + validator | One independently administered Linux host |
| Institution C | Authority + validator | One independently administered Linux host |
| Institution D | Authority + validator | One independently administered Linux host |
| Issuer service | CSR intake, certificate issuance and proposal coordination | Separate controlled Linux service; no authority private keys |

A fifth issuer host is recommended to separate issuance operations from validator administration. If the pilot cannot provision five hosts, the issuer may be hosted by one participant temporarily, but that institution's role conflict must be documented.

## Pilot phases

### Phase 0 — Governance and scope

Before connecting institutions, appoint a technical contact and an authorized certificate-policy owner at each organization. Agree on:
- Certificate purpose, subject fields, permitted claims and relying parties.
- Which organization is legally/operationally authorized to issue and revoke.
- Approval threshold (default 3-of-4 for this pilot), emergency revocation and dispute procedure.
- Data controller/processor roles, retention, incident notification and audit access.
- Test-only identities and non-production trust anchors. No real personal data or production credentials in the first network rehearsal.

### Phase 1 — Independent Linux installation

Each institution provisions a supported Linux host, dedicated service account, patched OS, time synchronization, firewall and private LAN/VPN endpoint. Record distribution/version, kernel, Python version, HUC commit SHA, hostname and operator.

Each node independently generates its validator identity. Each authority independently generates its authority signing identity. Private keys must never be copied to the issuer, another institution, CI artifacts or chat. Exchange only public descriptors and verify their fingerprints through a second authenticated channel.

### Phase 2 — Trust and network bootstrap

1. Agree on one network manifest and pin its SHA-256 out-of-band.
2. Agree on one peer map and pin its SHA-256 out-of-band.
3. Issue TLS server certificates whose SAN matches each peer-map DNS/IP.
4. Install only the TLS CA public certificate on nodes; keep CA signing keys offline.
5. Configure the firewall to allow the HUC peer port only between the four known endpoints.
6. Verify TLS and authenticated HUC peer status from every institution to every other institution.
7. Record connectivity, latency, packet loss and UTC clock offset.

Do not expose the experimental peer service directly to the public Internet.

### Phase 3 — Certificate lifecycle

Use synthetic test identities only:
1. Holder creates its own private key and CSR.
2. Issuer prepares an ISSUE proposal.
3. Each of the four authorities independently reviews the proposal and signs from its own host.
4. Issuer finalizes only with 3 distinct valid approvals.
5. Each institution receives and independently verifies the public credential and trust material.
6. Execute RENEW and confirm the predecessor becomes SUPERSEDED.
7. Execute REVOKE and confirm updated state evidence reports REVOKED.
8. Test offline verification with stale state evidence and confirm the documented freshness limitation is visible to relying applications.

### Phase 4 — BFT network and fault tests

Run four validators on four independent hosts. Require:
- 3-of-4 commit for a valid operation.
- No commit with only two reachable validators.
- Recovery after stopping the current primary with a prepared operation.
- No commit during a 2/2 network partition.
- Successful synchronization after connectivity returns.
- Rejection of replayed messages, altered payloads, duplicate/conflicting votes, stale state packages and rollback attempts.
- All four nodes converge to the same sequence and head hash.

Capture per-node logs and state before/after each test. A single-host four-process run is not a substitute for this phase.

### Phase 5 — Acceptance and decision

A pilot is accepted only when all four institutions sign the same evidence manifest and each required test has a recorded PASS/FAIL, operator, timestamp and artifact hash. Any unexplained divergence, unauthorized signature, rollback, inconsistent revocation result or quorum violation is a NO-GO.

## Production blockers to close before real certificates

The current repository remains experimental. At minimum, do not issue production certificates until these items are independently reviewed and resolved:

- **Private-key custody:** current helper code includes unencrypted PEM private-key storage for test/demo workflows. Replace with institution-controlled HSM/KMS or approved OS keystore integration, non-exportability where possible, rotation, backup/recovery and revocation procedures.
- **Durability and rollback resistance:** current JSON/file-based state and locks are not a production transactional database. Implement durable transactional storage, crash recovery, backup/restore and anti-rollback controls; test power loss and disk-full scenarios.
- **Transport identity:** current peer architecture documents TLS server authentication but not mandatory mutual TLS client certificates. Define and enforce institutional peer authentication, certificate rotation and revocation.
- **Protocol standardization:** freeze canonical serialization, schema/version negotiation, error codes and cross-language conformance vectors. The current JSON profile is implementation-specific and is not a complete RFC 8785 implementation.
- **Security assurance:** independent protocol/cryptographic review, threat model, penetration test, dependency/SBOM scanning, incident response and operational monitoring.
- **Certificate governance:** documented issuer authority, identity proofing, certificate policy, relying-party obligations, revocation publication and freshness SLAs.
- **Privacy and compliance:** data minimization, retention, access logging and legal review for each participating jurisdiction.

## Evidence bundle

For each rehearsal, preserve:
- HUC Git commit SHA and Linux workflow run URL.
- Four organization names or agreed pseudonymous IDs and named operators.
- Host/OS/Python details and validator/authority public-key fingerprints.
- Network-manifest, peer-map, trust-anchor and certificate hashes.
- Test-case matrix with results, timestamps and per-node sequence/head hashes.
- TLS and peer-status evidence, logs, latency and packet-loss measurements.
- SHA-256 hash for each artifact and signatures of all four institutional operators.

Never include private keys, access tokens, live personal data or unredacted production logs in the evidence bundle.
