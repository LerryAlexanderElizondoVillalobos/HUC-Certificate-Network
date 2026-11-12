# HUC Institutional Authority API — Linux User Mode

HUC complements existing X.509 credentials. The authority does not issue government certificates and does not replace the issuing CA.

## Architecture

- One logical HTTPS authority and one durable SQLite UTXO registry.
- Mandatory mutual TLS (mTLS): the server requires a client certificate signed by the configured client CA.
- Enrollment is an explicit SHA-256 fingerprint allowlist mapped to one of four independent institutional IDs.
- Every accepted consume is committed atomically with its hash-chained evidence event in the same SQLite transaction.
- SQLite WAL + synchronous FULL; state survives process restart.
- No nodes, root privileges, setuid, system daemon, or institution-operated blockchain nodes are needed.

## Install and start as an ordinary Linux user

```bash
python -m pip install -e .
python -m huc_institutional_authority --server-cert pki/server.crt --server-key pki/server.key --client-ca pki/institutional-client-ca.crt --client-registry config/institutional-clients.json --host 0.0.0.0 --port 8443
```

The server key and database must be readable only by the service account (private key mode 0600; state directory 0700; DB 0600). Use a firewall and a protected key store. Do not bind to a public interface until firewalling, certificate lifecycle, CRL/OCSP, operational monitoring and security review are complete.

## Endpoints

- `GET /health` — mTLS-authenticated health response.
- `POST /v1/consume` — JSON body `{"authorization": {...}}`; consumes one signed HUC authorization.
- `GET /v1/evidence` — returns the hash-chain evidence journal.

Unknown/un-enrolled client certificates are rejected. All four institutions must contact the same authority endpoint. Separate local databases do not provide cross-institution single-use guarantees.

## Enroll the four institutional clients

Issue four separate client certificates from the institution-approved client CA. Compute each DER certificate fingerprint:

```bash
openssl x509 -in institution-client.crt -outform DER | sha256sum
```

Replace the four placeholder fingerprints in `config/institutional-clients.json`. Keep private keys outside the repository. Each institution owns its own key and sends only signed authorization requests.

## Evidence and recovery

The consume row and evidence event share one SQLite transaction. After restart, `GET /v1/evidence` reconstructs and verifies the complete sequence, previous-hash links and event hashes. Back up the database with SQLite's online backup API or while the service is stopped; preserve WAL state. Restoring an old snapshot can re-enable spent outpoints, so production recovery requires a controlled checkpoint/epoch process and must never silently roll back authority state.

## Security limitations before production

- The mTLS trust CA and fingerprint enrollment are configuration trust inputs; secure their provisioning and change control.
- X.509 path validation and revocation are not performed by the HTTP layer. The current adapter explicitly reports revocation `NOT_CHECKED`; production must integrate approved trust anchors, policy/path validation and fresh CRL/OCSP checks.
- The first implementation is single-authority/single-host. High availability and federation are not included; do not run two independent authorities against copied databases.
- Four test identities prove client separation in integration tests, not real-world institutional readiness.
