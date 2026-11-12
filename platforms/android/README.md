# HUC Android Platform

Status: dedicated Kotlin/Gradle SDK and independent Android CI.

The current Android implementation lives at `sdk/direct/LAEV_HUC_Direct_SDK_v0.8.0/android/`. The independent workflow compiles the library and sample app and runs Android Keystore instrumentation on an API 35 emulator.

Target boundary: Android SDK, Keystore-backed signing, lifecycle, permissions and app integration. Private keys must remain inside Android Keystore where supported.