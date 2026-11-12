package org.bylaev.hucsample

import android.app.Activity
import android.os.Bundle
import android.util.Log
import org.bylaev.hucdirect.HucDirectClient

/**
 * Minimal integration scaffold. Replace the placeholder bundle/pin and call the
 * network API from a repository/WorkManager layer, not from the UI thread.
 */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 1. Create a holder key in Android Keystore. Private key is non-exportable.
        val holderKey = HucDirectClient.createHolderKey("huc-holder-demo")

        // 2. Create a CSR to send to the issuer API. The private key stays on-device.
        val csrPem = HucDirectClient.createCsr("Demo Student", holderKey.alias)
        Log.i("HUC", "CSR prepared (${csrPem.length} chars); submit CSR to issuer API")

        // 3. Once the issuer returns credential_bundle_b64, persist the public ZIP.
        // val bundle = Base64.getDecoder().decode(apiResponse.credential_bundle_b64)
        // val verification = HucDirectClient.verifyBundle(bundle, TRUST_ANCHOR_PIN)
        // require(verification.result == "VALID")

        // 4. For live holder proof, receive a challenge JSONObject from the relying party.
        // Show challenge.payload.audience to the user and obtain consent before signing.
        // val response = HucDirectClient.respondToChallenge(challenge, bundle, holderKey.alias)
        // POST response + challenge to /v1/direct/verify over HTTPS.
    }
}
