# LAEV HUC Direct Android SDK 0.8.0

## Modules

- `huc-direct`: Kotlin library for Android Keystore key generation, CSR creation, HUC package verification, direct challenge signing and REST relying-party calls.
- `sample`: minimal Activity showing the holder CSR lifecycle.

## Build

Open this `android/` folder in Android Studio with JDK 17 and Android SDK Platform 35, or build with an installed Gradle 8.9+ distribution:

```bash
gradle :huc-direct:assembleRelease
# optional sample app:
gradle :sample:assembleDebug
```

The library declares minSdk 26 and uses Bouncy Castle 1.80 and OkHttp 4.12.0.

**Build validation status:** this delivery environment did not contain Gradle or an Android SDK, so the Kotlin/Gradle project has not been compiled here. Treat it as integration source that requires a local Android Studio build, unit tests and instrumented tests on supported devices before release. AndroidKeyStore provider and RSA/Ed25519 support must be checked on the OEM/API levels being targeted.

## Security

The SDK does not expose an issuer administrator token. The Android app creates the holder key and CSR; an authenticated institutional backend forwards the CSR to the issuer service. The backend returns the public credential ZIP. Holder private key material stays in Android Keystore.

`HucDirectApiClient` uses synchronous OkHttp calls. Execute calls off the UI thread (coroutines IO dispatcher, executor or WorkManager). Production URLs must use HTTPS.
