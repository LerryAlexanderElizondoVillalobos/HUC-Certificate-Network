# HUC Funding Sandbox — reproducible synthetic tests

## Scope and safety

This lab tests contribution/payment lifecycle mechanics that may be used to fund the HUC project. It is not a lender, bank, payment processor, credit-scoring system or production integration.

- Every balance is synthetic and in-memory.
- No payment provider, bank account, card network, wallet or external API is contacted.
- No real funds move.
- A certificate SHA-256 may be attached as an evidence reference only. It is not proof of solvency, creditworthiness, identity, legal authority or repayment capacity.
- Do not add production credentials or live API keys to this lab.

## Run locally

From the repository root:

```bash
python -m unittest tests.test_funding_sandbox -v
```

The cross-platform workflow runs this suite on Ubuntu, Windows and macOS. JUnit XML output is uploaded as a GitHub Actions artifact.

## Simulated lifecycle

1. Create a contribution/payment intent using a unique idempotency key.
2. Authorize the synthetic intent.
3. Capture it, increasing only the in-memory synthetic balance.
4. Refund partially or fully, reducing the synthetic balance.
5. Verify the append-only SHA-256 hash chain in the evidence report.

The simulator rejects duplicate idempotency keys with different payloads, capture before authorization, refunds exceeding captured value, invalid certificate digest references and invalid event-chain hashes.

## Evidence

The `FundingSandbox.evidence()` report includes:

- `mode = SYNTHETIC_NO_EXTERNAL_PROVIDER`
- currency and synthetic balance
- ordered events and sequence numbers
- previous-event hashes and event hashes
- event count, head hash and local chain-verification result

This evidence proves only that the simulator's test sequence ran and its local hash chain is internally consistent. It does not prove settlement, payment-provider execution or receipt of real funds.

## Future provider sandbox

A real provider sandbox adapter is a separate integration. Before selecting Stripe, PayPal or a bank API, define the funding model, provider, legal entity, supported countries/currencies, refund/dispute rules and webhook trust model. Use the provider's official test environment and test credentials stored as repository secrets. Keep live-mode credentials and live endpoints out of the CI workflow.
