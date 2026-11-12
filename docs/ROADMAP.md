# HUC Roadmap

## Current baseline — 0.8.0 experimental reference
- [x] X.509 credential lifecycle: issue, renew and revoke
- [x] HUC-CC signed authorization evidence
- [x] Logical UTXO state and hash-linked history
- [x] Independent authority approval and membership workflow
- [x] BFT-inspired prepare, prepared locks, commit and quorum certificates
- [x] View change, prepared recovery and state synchronization
- [x] TCP/TLS peer transport and automated tests
- [x] Public test fixtures and offline verification examples

## Next — CI and protocol hardening
- [ ] Run full test suite on supported Python versions in GitHub Actions
- [ ] Add coverage reporting and minimum coverage policy
- [ ] Add fuzz/property-based tests for parsers and signed messages
- [ ] Publish deterministic cross-language test vectors
- [ ] Review TLS/mTLS deployment profile and key rotation
- [ ] Independent protocol and cryptographic audit

## Production-readiness research
- [ ] Transactional durable storage and anti-rollback protections
- [ ] Formal safety/liveness analysis under explicit network assumptions
- [ ] Four-device and multi-institution WAN test
- [ ] Backup, recovery, monitoring and incident-response procedures
- [ ] Stable HUC Direct SDK API and Android integration tests
- [ ] Versioned interoperability specification
