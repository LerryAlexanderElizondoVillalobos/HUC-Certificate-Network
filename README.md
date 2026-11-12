# LAEV HUC Certificate Network 0.8.0

**HUC — Hybrid UTXO Certificate** is an experimental certificate infrastructure combining X.509 credentials, signed HUC-CC authorization evidence, a logical UTXO lifecycle and an optional replicated BFT-inspired state network.

> Status: experimental laboratory implementation. Not a blockchain, cryptocurrency, formally verified BFT protocol, production-certified PKI or independent security-audited system.

## Core capabilities

- X.509 certificate issuance, renewal and revocation.
- HUC-CC signed authorization and certificate binding.
- Logical UTXO state with sequence and hash-chain continuity.
- Independent authority approvals and membership management.
- Replicated state across independent validators.
- PRE-PREPARE, PREPARE, prepared-lock acknowledgements and COMMIT.
- Signed view change, prepared-operation recovery and state synchronization.
- TCP peer transport, TLS transport security and Ed25519 application signatures.
- Public verification bundles that do not contain issuer or validator private keys.

## Architecture profiles

**Standalone / HUC Direct:** a verifier can validate a signed credential package offline using a separately distributed trust anchor and state attestation. It does not require validators or a network connection for basic package verification.

**Replicated / HUC BFT:** institutions operate independent validators to agree on shared certificate state. This is an optional deployment profile for shared state, not a prerequisite for local credential verification. The HUC 0.8 BFT implementation is PBFT-inspired and adds a HUC-specific prepared-lock acknowledgement stage; it is not claimed to be formally equivalent to PBFT.

## Requirements

- Python 3.10+
- `cryptography>=42.0.0`
- `filelock>=3.13.0`

## Install and test

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

The four-process TLS cluster test can be run independently:

```bash
python -m unittest tests.test_bft_process_cluster -v
```

## Repository map

- `huc.py`: X.509, HUC-CC, logical UTXO and certificate lifecycle.
- `huc_bft.py`: BFT-inspired state machine, quorum certificates and recovery.
- `huc_bft_peer.py`: BFT phase orchestration over peer transport.
- `huc_peer.py`: authenticated TCP/TLS peer transport.
- `huc_replicated.py`: replicated state and synchronization.
- `huc_federation.py`: independent authority approval workflow.
- `huc_membership.py`: validator membership transitions.
- `huc_view.py`: view-change and recovery data structures.
- `tests/`: automated unit, adversarial, network and cluster tests.
- `demo/`: public demonstration fixtures and verification scripts.
- `docs/`: protocol, architecture, security and physical-device procedures.
- `.github/workflows/`: CI, security and integration automation.

## Security boundaries

The repository includes experimental security controls, but no independent cryptographic audit, formal verification, production hardening or physical multi-institution deployment certification has been completed. The TLS cluster test runs four processes on one host using loopback; it is not evidence of WAN, NAT or four-device interoperability. See [Security](docs/SECURITY.md) and [Physical device test](docs/PHYSICAL_DEVICE_TEST.md).

Never commit private keys, live credentials, production certificates or real personal data. Public demo fixtures are not production trust anchors.

## Version reference

The original HUC 0.8.0 source and public test packages remain preserved in `docs/` as versioned reference archives. See [Release notes](docs/RELEASE_NOTES_0.8.0.md), [Architecture](docs/ARCHITECTURE.md) and [Protocol](docs/PROTOCOL.md).

## Commercial rights

No open-source license is granted by this repository unless a LICENSE file explicitly states otherwise. All rights are reserved by the copyright holder. Commercial use, redistribution and derivative distribution require written permission or a separate license.
