# ADR-0001 — Institutional-first authorization and optional federation

- **Status:** Accepted for HUC 0.8.0 architecture
- **Scope:** Linux implementation; external X.509 integration; single-use UTXO authorization
- **Decision:** HUC is an institutional one-time-use authorization infrastructure. It is not a blockchain deployment that requires institutions to operate nodes before the first useful operation.

## 1. Core decision

HUC MUST operate from first installation in Linux User Mode without a node network, quorum, blockchain process, root privileges, setuid binary, or system-wide daemon. Institutional communication with one logical authoritative UTXO service is the default shared-state model.

Node federation is an optional evolution path. It MUST NOT be a prerequisite for installation, local development, certificate verification, or the first institutional pilot.

## 2. Preserve X.509

HUC complements externally issued X.509 certificates. It does not replace the issuing CA, the certificate's legal identity meaning, or the institution's trust policy. The X.509 credential identifies the certificate holder and supplies the public key used to verify the holder's signature. HUC binds a separate authorization to that certificate fingerprint, operation, resource, expiry, nonce, and UTXO outpoint.

Certificate path validation and revocation status are separate requirements. A bounded chain check with `revocation_status=NOT_CHECKED` is not production certificate validation. Production acceptance requires the institution's approved trust anchors, applicable path/policy checks, and sufficiently fresh CRL/OCSP status; unknown or stale revocation status MUST fail closed.

## 3. Institutional mode — default

- One logical authority owns the authoritative consumed-outpoint registry.
- Institutional applications communicate with it over authenticated HTTPS; mTLS is the preferred institutional client-authentication profile.
- A single-host SQLite registry may be used for the first Linux deployment, with atomic transactions and a unique outpoint constraint.
- All institutions requiring global single-use semantics MUST consult the same logical authority. Four disconnected SQLite databases cannot prevent cross-institution double-spend.
- The authority process runs as an ordinary Linux user, without sudo/root, setuid, or mandatory system daemon.
- State is stored under an owner-controlled directory, preferably `$XDG_STATE_HOME/huc` or `$HOME/.local/state/huc`, with directory mode 0700 and database/key-material permissions no broader than 0600. HUC must not copy institution private keys into its database.
- On communication failure, a client may queue a request, but MUST NOT claim a globally unique consume succeeded. The authority is the only component that can confirm consumption.

## 4. Standalone verification versus shared consumption

Offline verification of a signed certificate/evidence package is supported when the verifier has an independently provisioned trust anchor and signed state evidence. It cannot learn about a revocation or spend that occurred after the evidence was issued unless updated evidence is delivered.

A standalone local registry guarantees uniqueness only within that registry. It does not provide global uniqueness among disconnected institutions. This limitation MUST be explicit in product output and documentation.

## 5. Federated mode — optional

The existing replicated/BFT components may be enabled later. Every spend then requires a valid commit certificate under the configured quorum. If quorum is unavailable, the system MUST fail closed and MUST NOT fall back to local SQLite spending.

The federation implementation remains experimental until independent protocol review, multi-host testing, recovery/rollback testing, key-custody review, and security audit are completed. Four processes on loopback are not proof of four independent institutional nodes.

## 6. Controlled migration

Standalone-to-federated migration MUST be exclusive:
1. Stop new spends and place the standalone authority in read-only/frozen mode.
2. Create a consistent database snapshot and verify all records, outpoints, event hashes, and the current state head.
3. Produce a signed migration manifest containing database hash, state head, record count, source authority ID, epoch, and timestamp.
4. Import and independently verify the snapshot on every target validator.
5. Obtain explicit quorum acceptance of the same migration manifest and epoch.
6. Switch the service to federated mode only after acceptance; preserve the source snapshot as read-only evidence.

The old and new authorities MUST NOT accept spends concurrently. Rollback to an older snapshot MUST NOT resume spending without an explicit, auditable epoch/checkpoint recovery decision.

## 7. Linux acceptance criteria

HUC 0.8.0 Linux User Mode is not considered complete until automated tests demonstrate:
- installation and execution by a non-root user;
- no need for sudo, setuid, or system daemon;
- secure state-directory and database permissions;
- durable state across restart;
- atomic concurrent consume with exactly one winner;
- rejection of replay, expiry, wrong certificate binding, and invalid signatures;
- authenticated institutional API access and fail-closed behavior when the authority is unavailable;
- exportable, verifiable evidence for each successful consume.

## 8. Four-institution pilot sequence

The first rehearsal uses four independent institutional clients against one authoritative Linux service. The institutions do not need to operate nodes. Use synthetic or explicitly authorized test X.509 certificates only. After the centralized institutional mode passes, repeat the lifecycle against the optional four-validator federation.

The pilot must distinguish the Legislative Assembly, Executive Power, Judicial Power, and the autonomous Supreme Electoral Tribunal (TSE). Each institution uses its own client identity and certificate profile. No live personal data or private keys enter the repository.

## 9. Consequences

This decision prioritizes immediate usability and a clear trust boundary. It accepts a single logical authority as the initial availability and trust dependency. High availability can later be added through a redundant service/database architecture or the optional federated consensus profile, without changing the authorization payload or institutional client contract.
