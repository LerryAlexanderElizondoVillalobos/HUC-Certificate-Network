# HUC Deployment Profiles

HUC supports two complementary deployment profiles. They must not be conflated.

## Standalone credential verification

A relying application receives a public credential package containing X.509, HUC-CC and the applicable signed state evidence. It verifies the package locally against a trust anchor obtained independently. Basic verification can be offline. The issuer remains responsible for publishing current state/revocation evidence.

## Replicated institutional state

Independent validators maintain a common replicated UTXO state. HUC BFT coordinates ISSUE, RENEW and REVOKE transitions with quorum certificates, prepared locks, view change and verified synchronization. This profile requires network connectivity between validators.

## HUC Direct SDK

HUC Direct SDK is an application integration layer, not a replacement for the BFT protocol. It can support local issuance/presentation/verification workflows and optionally consult an issuer or replicated-state service for fresh status. Android Keystore protects holder private keys from export.

## Trust boundaries

- X.509 proves a certificate chain under a configured CA.
- HUC-CC binds authorization policy and certificate evidence.
- UTXO state represents lifecycle transitions.
- BFT validators agree on shared state under the documented fault assumptions.
- A standalone verifier trusts the trust anchor and signed state evidence it receives.

Offline verification cannot independently know about a revocation that has not been delivered to it. A BFT quorum does not make an issuer's claims factually true or legally authorized.
