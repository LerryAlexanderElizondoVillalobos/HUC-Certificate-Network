# HUC Direct SDK 0.8.0

The Direct SDK is the application-facing integration layer for HUC. It is intentionally separate from the optional HUC BFT validator network.

## Packages

- `direct/LAEV_HUC_Direct_SDK_v0.8.0/python/`: Python issuer, verifier, presenter and optional REST API.
- `direct/LAEV_HUC_Direct_SDK_v0.8.0/android/`: Kotlin library and sample application using Android Keystore.
- `demo/LAEV_HUC_Direct_SDK_Demo_v0.8.0/`: public credential lifecycle and challenge-response fixtures.

## Python tests

```bash
cd sdk/direct/LAEV_HUC_Direct_SDK_v0.8.0/python
python -m pip install -e ".[api,test]"
python -m pytest -q ../tests
```

The SDK's own build report records 19 passing Python unit/integration tests. GitHub Actions now reruns these tests independently.

## Android status

The Kotlin/Gradle project is included. The original 0.8.0 build report records that it was not compiled in its development environment because Android SDK/Gradle were unavailable. A successful Android CI build and physical-device Keystore testing remain release gates.

## Trust model

The holder's private key is generated and retained locally (Android Keystore on Android). The issuer receives public CSR material. Credential verification can be offline against a separately provisioned trust anchor and signed state evidence; freshness and revocation awareness depend on the verifier's configured state-evidence policy.
