# HUC Costa Rica — Institutional Public-Key Credential Architecture

## Status and scope

This document defines a proposed HUC deployment profile for Costa Rica's constitutional institutions. It is an architectural and technical proposal, not a legal opinion, procurement authorization, government endorsement, or claim of approval by any institution.

The constitutional framing is precise: Article 9 recognizes three distinct and independent State Powers — Legislative, Executive and Judicial — and separately establishes the Supreme Electoral Tribunal (TSE) with the rank and independence of the Powers of the State and exclusive electoral functions. HUC must therefore model four independent institutional domains without casually redefining the TSE as a fourth Power or subordinating it to the other three.

## Primary design decision

HUC is a federated credential, certificate-lifecycle and verifiable-evidence infrastructure. It is not a replacement for the National Digital Certification System, the MICITT Root Certification Authority, SINPE CA, institutional legal powers, or statutory procedures.

For legally certified digital signatures, HUC must interoperate with certificates issued under the applicable Costa Rican national certification hierarchy and requirements. HUC must not label its own experimental certificates as Ley 8454 certified signatures or claim equivalent legal effect unless the issuing certification service is legally authorized and complies with the applicable registration, policy, security and audit requirements.

A useful first HUC credential is an **institutional role / authority / service credential** that binds:
- a public-key identifier to a person, office, service or system;
- the issuing institutional domain and responsible authority;
- role, scope, permitted actions and delegation constraints;
- validity interval and policy version;
- status/evidence references for issuance, renewal, suspension and revocation;
- references to any external national digital certificate used for legal document signatures.

The HUC credential complements — it does not silently replace — the legal digital signature certificate.

## Four independent institutional domains

1. Legislative Power.
2. Executive Power.
3. Judicial Power.
4. Supreme Electoral Tribunal (TSE), separately modeled as an independent constitutional institution with its own electoral competences.

Each domain controls its own:
- identity proofing and registration process;
- institutional role/authority policy;
- issuer authorization and approval workflow;
- authority keys, validator operations and security administrators;
- certificate/credential issuance, renewal, suspension and revocation decisions;
- audit trail and retention obligations.

No domain may issue, revoke, suspend, or delegate powers in another domain merely because it participates in a shared HUC network.

## No cross-institution 3-of-4 veto over institutional decisions

Do not apply the experimental 3-of-4 approval threshold across the four constitutional domains to every issuance or revocation. Such a mechanism could wrongly imply that one institution can veto or authorize another institution's legally assigned acts.

Each domain's authorized officials decide credentials within their competence under their own policy. Shared HUC validators may order and replicate cryptographic evidence, but consensus validates protocol state; it does not decide whether a public official has legal authority, whether an administrative act is lawful, or whether another Power should issue a credential.

If a specific inter-institutional credential requires multiple organizations' consent, define that as a separate, explicit multi-party policy for that use case, with legal approval and named signatories.

## Linux reference architecture

For the initial deployment, use Linux as the reference runtime with independently operated institutional nodes. Each institutional domain should have:
- an identity/registration service;
- an institutional issuer or approved integration to an existing certification authority;
- a validator node, if participation in shared consensus is approved;
- a hardware-backed or institutionally approved key-management service;
- a durable transactional state store;
- authenticated, encrypted peer transport with mutual TLS;
- an audit and monitoring service;
- offline verification capability with explicit status-freshness limits.

A separate coordination or public verification service may distribute public trust metadata and proofs. It must not hold institutional signing keys or make decisions on behalf of institutions.

## Credential lifecycle and first-install guarantee

The first trust package installed by a relying institution must be sufficient to validate the first credential and remain upgradeable without silently changing trust:
1. install a signed trust bundle containing approved trust anchors, issuer identifiers, policy identifiers, schema versions and supported algorithms;
2. verify trust-bundle signature and pinned fingerprint through an independent channel;
3. register or verify the subject identity and institutional authority;
4. issue the credential under the correct institutional domain;
5. publish the credential and signed status evidence;
6. verify it independently from each relying institution;
7. renew by creating a successor credential and preserving verifiable history;
8. suspend or revoke with authenticated reason codes and signed status evidence;
9. distribute trust and status updates with versioning, rollback protection and transparency/audit evidence.

No update may replace trust anchors or reinterpret old signatures without an explicit, signed, policy-governed transition. A relying party must be able to distinguish VALID, EXPIRED, SUSPENDED, REVOKED, UNKNOWN and STALE_STATUS; unknown or stale status must never be reported as valid.

Offline validation can verify signatures and the most recently available signed status evidence, but cannot guarantee detection of a revocation that occurred after that evidence was issued. Define maximum status age and relying-party behavior for stale evidence.

## UTXO state model

HUC's UTXO representation may track credential lifecycle:
- ISSUE creates an active credential-state output;
- RENEW consumes the predecessor state and creates a successor state;
- SUSPEND changes the state according to the credential policy;
- REVOKE consumes or closes the active state and records an irreversible revocation event;
- RESTORE, if legally and technically permitted, must be a new explicit event under policy, never deletion of history.

UTXO state is technical evidence of lifecycle, not by itself proof that the underlying administrative decision was legally valid. Bind every transition to an authorized institutional signature, policy version, timestamp evidence and audit record.

## Minimum production requirements

Do not deploy production institutional credentials until the following have passed independent review:
- hardware-backed key custody, separation of duties, rotation, recovery and compromise response;
- durable transactional database, atomic state transitions, crash recovery, backups and tested restore;
- anti-rollback and replay protection;
- mutual TLS with institutional peer identity, certificate rotation and revocation;
- canonical serialization and published cross-implementation test vectors;
- independent cryptographic/protocol security review and penetration test;
- software bill of materials, dependency pinning, vulnerability management and signed releases;
- high availability, monitoring, alerting, disaster recovery and incident response;
- legal review of institutional competence, data protection, archives, procurement and applicable digital-signature rules;
- accessibility, records management, retention and audit export.

## Pilot stages and acceptance

### Stage 1 — Non-production conformance
Build four isolated institutional domains using synthetic identities and test keys. Verify independent issue, renewal, suspension, revocation and offline/online validation. Prove that no institution can administer another domain.

### Stage 2 — Four-host network
Deploy one Linux node per participating institutional domain on separately administered hosts and network segments. Test loss of one node, 2/2 partition, replay, clock skew, recovery, backup/restore, stale status and cross-domain isolation. Capture signed evidence from every operator.

### Stage 3 — Controlled institutional pilot
Only after legal, security and operational approval, use a limited set of non-critical institutional roles or service identities. Do not replace legally required national digital signatures in this stage.

### Stage 4 — Production decision
Each participating institution's authorized governance and security bodies independently approve its participation. A joint technical acceptance does not replace any institution's statutory authorization.

Acceptance requires:
- all four domains independently verify the same authorized cross-domain test credentials;
- no cross-domain unauthorized issuance, suspension or revocation is possible;
- all nodes converge on identical committed evidence;
- a one-node failure does not violate the documented safety guarantees;
- recovery and rollback tests pass;
- first-install trust package, upgrade and revocation freshness behavior are documented and verified;
- complete signed evidence bundle and independent security/legal sign-off.

## Institutional governance warning

HUC must preserve the constitutional independence and assigned competences of each domain. The shared protocol is a technical interoperability mechanism, not a superior authority over the Legislative, Executive, Judicial Powers or the TSE.
