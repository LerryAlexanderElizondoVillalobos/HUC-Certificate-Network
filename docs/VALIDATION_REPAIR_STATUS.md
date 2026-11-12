# HUC 0.8.0 — Validation repair status

**Branch:** `validation/huc-0.8.0-multiplatform`  
**Pull request:** https://github.com/LerryAlexanderElizondoVillalobos/HUC-Certificate-Network/pull/2  
**Certificate specification:** unchanged  
**Release version:** unchanged at 0.8.0

This document distinguishes code changes from completed test evidence. A workflow queued or a test job skipped is not a PASS.

## Work completed in the validation branch

| Work item | Change made | Evidence status |
|---|---|---|
| Windows BFT VIEW_CHANGE | Increased network deadlines for the prepared-recovery scenario; quorum and state assertions remain unchanged | Awaiting repeat CI result |
| Windows Python 3.10 and 3.11 | Matrix explicitly includes 3.10, 3.11, 3.12 and 3.13; focused BFT regression runs on all four | Awaiting repeat CI result |
| Android X.509 comparison | Uses `issuerX500Principal` and `subjectX500Principal` from Java X509Certificate API | Awaiting Gradle build result |
| Android Keystore | Added instrumentation test for non-exportable RSA holder key and signed CSR | Awaiting emulator result |
| Android emulator | Added API 35 Google APIs emulator job | Awaiting execution |
| Android physical device | Added optional self-hosted job gated by `HUC_PHYSICAL_DEVICE_RUNNER=enabled` | Not run; requires an enrolled runner and USB-connected device |
| Funding sandbox | Added synthetic authorize/capture/refund tests and a JSON evidence exporter with SHA-256 event chain | Awaiting cross-platform CI result |
| Four independent devices | Added acceptance procedure and evidence template | Not run; requires four actual devices and an operator-controlled network |

## Funding sandbox scope

The sandbox uses synthetic in-memory USD values only. It tests idempotency, authorization, capture, partial/full refunds, over-refund rejection and event-chain integrity. It does not contact a provider, move money, prove bank settlement or underwrite loans. A certificate digest is only a reference in the test record, not a creditworthiness signal.

Run locally:

```bash
python -m unittest tests.test_funding_sandbox -v
python -m validation.run_funding_sandbox --output funding-sandbox-evidence.json
```

The exporter should report `real_funds_moved: false`, a valid event chain and a final synthetic balance of `0.00`.

## Four-device acceptance boundary

The existing four-process TLS test runs four independent processes on one hosted Linux machine. It is not a four-host or four-institution test. The physical acceptance procedure is documented in [FOUR_DEVICE_TEST_EXECUTION.md](FOUR_DEVICE_TEST_EXECUTION.md) and [PHYSICAL_DEVICE_TEST.md](PHYSICAL_DEVICE_TEST.md).

## Release gate

Do not merge this PR, change the HUC certificate specification or increment the version until:

1. Windows BFT regression passes on Python 3.10–3.13.
2. The complete Linux, Windows and macOS core/SDK matrices pass.
3. Android library/sample build and API 35 emulator instrumentation pass.
4. Physical Android instrumentation is executed and recorded when a device runner is provisioned.
5. Funding sandbox tests pass on Linux, Windows and macOS and JSON evidence artifacts are reviewed.
6. Four-device acceptance is executed on four actual hosts and all state heads match.
