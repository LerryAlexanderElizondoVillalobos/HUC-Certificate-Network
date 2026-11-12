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
python -m huc_institutional_authority --server-cert pki/server.crt --server-key pki/server.key --client-ca pki/institutional-client-ca.crt --client-registry config/institutional-clients.json --trust-bundle pki/approved-roots.pem --crl-bundle pki/current-crls.pem --policy-oid 1.2.3.4.5 --revocation crl --host 0.0.0.0 --port 8443
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


## X.509 signer validation (fail-closed)

The mTLS client certificate identifies the institution's API client. It is NOT treated as the official's signing certificate. Every consume request must include `signer_certificate_pem`, optional `signer_chain_pem`, and the signed authorization. HUC separately verifies the signer certificate against the out-of-band trust bundle, an institution-approved certificate-policy OID, and the configured revocation source before checking the HUC authorization signature.

- `--trust-bundle`: pinned, institution-approved trust roots; never fetch trust roots from AIA.
- `--policy-oid`: mandatory policy OID agreed with the certificate issuer/policy authority.
- `--revocation crl`: requires a fresh provisioned CRL bundle covering every issuer in the path.
- `--revocation ocsp`: queries OCSP responder URLs in signed AIA; unavailable/unknown/revoked is rejected.
- `--revocation both`: requires both CRL and OCSP to succeed.

The OpenSSL verifier enforces path signatures, validity, strict X.509 constraints, security level 2, the configured certificate policy and full-chain CRL checking. This is still subject to deployment-specific policy review and does not establish that Costa Rica's public-sector PKI accepts the selected OID or trust roots.

## Rollback-resistant recovery

The service writes a monotonic sequence/head-hash anchor beside the database using atomic replace and fsync. Startup rejects a database whose event head is behind or forks from the anchor. The anchor is deliberately separate from the SQLite backup.

**Important limitation:** a local sidecar anchor detects restoration of only the database, not an attacker restoring both database and anchor together. Production must store/replicate the anchor in a separately administered, append-only location (e.g. immutable object storage or a trusted institutional witness) and require that external checkpoint during recovery. Do not claim protection against coordinated rollback until that external anchor is deployed and tested.

For backups use SQLite's online backup API; preserve the database and WAL consistently. Test restoration into an isolated environment first. Reconcile the restored head against the independently protected external checkpoint before permitting consumption.
