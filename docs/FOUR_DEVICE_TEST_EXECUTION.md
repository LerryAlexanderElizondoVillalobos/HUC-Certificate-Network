# HUC 0.8.0 — Four independent device test execution record

## Current evidence boundary

GitHub Actions can run multiple processes and containers on a hosted runner, but that is not four independent physical devices or four independent institutional networks. No physical four-device test is claimed by this repository until the evidence below is supplied and reviewed.

The existing `tests/test_bft_peer.py` exercises four logical validators using TCP peer servers in one Python test process. The Linux `tests/test_bft_process_cluster.py` test launches four separate OS processes and uses TLS over TCP loopback on one host. Both are useful integration tests, but neither proves multi-host behavior.

## Required test topology

| Validator | Device | Owner / institution | OS | Network endpoint |
|---|---|---|---|---|
| HUC-A | To be recorded | To be recorded | To be recorded | To be recorded |
| HUC-B | To be recorded | To be recorded | To be recorded | To be recorded |
| HUC-C | To be recorded | To be recorded | To be recorded | To be recorded |
| HUC-D | To be recorded | To be recorded | To be recorded | To be recorded |

Use four distinct devices and four independently generated HUC private keys. Do not copy private keys between nodes. Use a private LAN or VPN, TLS server certificates with SANs matching the peer-map endpoints, and firewall rules that permit only the four test nodes.

## Acceptance sequence

1. Record device identifiers, OS build, Python version, HUC commit SHA and network conditions.
2. Generate four independent validator identities and distribute only public descriptors.
3. Create and independently pin the network manifest and peer map.
4. Establish TLS connections in both directions; record each peer's authenticated status.
5. Issue one test certificate and submit one ISSUE operation.
6. Require the 3-of-4 quorum and compare `sequence` and `head_hash` on all four devices.
7. Stop the primary after PREPARED evidence is persisted; execute VIEW_CHANGE and recovery.
8. Partition the network 2/2; confirm no quorum commit occurs.
9. Reconnect all nodes; synchronize and confirm identical state.
10. Replay a signed message, alter a payload, and attempt conflicting votes; all must be rejected.
11. Export logs and a signed test manifest. Hash each artifact with SHA-256.

## Evidence record

For every run, attach:

- Four device/OS/runtime records and four validator public IDs.
- Peer-map hash, network-manifest hash and test certificate hashes.
- TLS connection evidence from each node.
- Per-node sequence/head hash before and after each scenario.
- UTC timestamps, latency and packet-loss measurements.
- Logs from all four nodes and exact Git commit SHA.
- SHA-256 hashes of every evidence artifact.
- Pass/fail result for each acceptance step and an operator sign-off.

## How to run from GitHub Actions

The current hosted workflow runs the four-process TLS cluster test on Ubuntu. It is a regression gate, not a physical-device acceptance test. A physical test requires four accessible devices and an operator-controlled LAN/VPN. A future self-hosted runner workflow may automate evidence collection after four independently administered runners are provisioned and securely enrolled; it must not silently substitute one host with four labels.
