# HUC Direct SDK 0.8 public demo

- `credential-active.zip`: active X.509 + HUC-CC + UTXO state.
- `credential-renewed-active.zip`: the renewed credential.
- `credential-superseded.zip`: the predecessor after renewal.
- `credential-revoked.zip`: the renewed credential after revocation.
- `direct-challenge.json` and `direct-response.json`: sample of the optional holder challenge exchange. The challenge expires after five minutes; use fresh challenges for actual testing.
- `public-metadata/`: public CA, public issuer key, policy, trust anchor and public certificate evidence.
- `trust-anchor.sha256`: out-of-band trust pin for this demo only.

No private keys are included. The private keys used to generate these files were created in a temporary workspace and removed after generation.
