package org.bylaev.hucdirect

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.StringReader
import java.io.StringWriter
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.Duration
import java.time.temporal.ChronoUnit
import java.util.Base64
import java.util.zip.ZipInputStream

/** LAEV HUC Direct SDK 0.8.0. No node network or blockchain required. */
object HucDirectClient {
    private const val PACKAGE_SCHEMA = "LAEV-HUC-PACKAGE-1"
    private const val CC_TYPE = "LAEV-HUC-CC"
    private const val STATE_SCHEMA = "LAEV-HUC-STATE-1"
    private const val CHALLENGE_SCHEMA = "LAEV-HUC-DIRECT-CHALLENGE-1"
    private const val RESPONSE_SCHEMA = "LAEV-HUC-DIRECT-RESPONSE-1"
    private const val MAX_ZIP_BYTES = 10 * 1024 * 1024
    private const val DOMAIN = "LAEV-HUC-DIRECT-CHALLENGE/0.8"

    init {
        if (Security.getProvider("BC") == null) Security.addProvider(BouncyCastleProvider())
    }

    data class VerificationResult(
        val result: String,
        val hybridValid: Boolean,
        val subject: String,
        val serialNumber: String,
        val certificateSha256: String,
        val utxoStatus: String,
        val stateFreshnessValid: Boolean,
        val stateAgeSeconds: Long,
        val issuerId: String,
        val trustAnchorSha256: String
    )

    data class HolderKey(val alias: String, val publicKey: PublicKey)

    /** Generates an RSA key in Android Keystore. The private key is non-exportable. */
    fun createHolderKey(alias: String, keySize: Int = 2048): HolderKey {
        require(alias.isNotBlank()) { "Keystore alias required" }
        require(keySize in 2048..4096) { "RSA key size must be 2048..4096" }
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setKeySize(keySize)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .setUserAuthenticationRequired(false)
            .build()
        generator.initialize(spec)
        val pair = generator.generateKeyPair()
        return HolderKey(alias, pair.public)
    }

    /** Creates a PEM CSR using an Android Keystore private key; the key never leaves Keystore. */
    fun createCsr(commonName: String, alias: String): String {
        require(commonName.isNotBlank()) { "Common Name required" }
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val privateKey = store.getKey(alias, null) as? PrivateKey ?: error("No private key for alias")
        val cert = store.getCertificate(alias) ?: error("No public certificate for alias")
        val publicKey = cert.publicKey
        val subject = X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, commonName).build()
        val builder = JcaPKCS10CertificationRequestBuilder(subject, publicKey)
        val signature = Signature.getInstance("SHA256withRSA", "AndroidKeyStore")
        signature.initSign(privateKey)
        val contentSigner = object : ContentSigner {
            private val output = ByteArrayOutputStream()
            override fun getAlgorithmIdentifier() = DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA")
            override fun getOutputStream() = output
            override fun getSignature(): ByteArray {
                signature.update(output.toByteArray())
                return signature.sign()
            }
        }
        val csr = builder.build(contentSigner)
        val writer = StringWriter()
        JcaPEMWriter(writer).use { it.writeObject(csr) }
        return writer.toString()
    }

    /** Offline verification: trust pin must be obtained independently of the ZIP. */
    fun verifyBundle(bundle: ByteArray, expectedTrustAnchorSha256: String,
                     maxStateAgeSeconds: Long = 300): VerificationResult {
        require(bundle.size <= MAX_ZIP_BYTES) { "Credential package too large" }
        require(expectedTrustAnchorSha256.matches(Regex("[0-9a-fA-F]{64}"))) { "External trust pin required" }
        val files = unzip(bundle)
        val requiredEntries = setOf("package_manifest.json", "ca_certificate.pem", "issuer_public.pem", "huc_policy.json", "trust_anchor.json", "certificate.pem", "consensus_certificate.json", "state_attestation.json")
        require(files.keys == requiredEntries) { "Credential package contains missing or unexpected files" }
        val manifest = json(files, "package_manifest.json")
        require(manifest.optString("schema") == PACKAGE_SCHEMA && manifest.optString("version") == "0.8.0") { "Unknown HUC package schema/version" }
        require(!manifest.optBoolean("private_keys_included", true)) { "Package claims private keys included" }
        val certBytes = files["certificate.pem"] ?: error("certificate.pem missing")
        val cc = json(files, "consensus_certificate.json")
        val state = json(files, "state_attestation.json")
        val caBytes = files["ca_certificate.pem"] ?: error("CA certificate missing")
        val issuerPem = String(files["issuer_public.pem"] ?: error("Issuer key missing"), Charsets.US_ASCII)
        val policy = json(files, "huc_policy.json")
        val anchor = json(files, "trust_anchor.json")
        val cert = x509(certBytes)
        val ca = x509(caBytes)
        val issuerPublic = ed25519Public(issuerPem)
        val certHash = hex(sha256(cert.encoded))
        require(certHash == manifest.optString("certificate_sha256_der")) { "X.509 package hash mismatch" }
        require(hex(sha256(canonical(cc))) == manifest.optString("consensus_certificate_sha256")) { "HUC-CC package hash mismatch" }
        require(hex(sha256(files["state_attestation.json"]!!)) == manifest.optString("state_attestation_sha256")) { "State attestation package hash mismatch" }
        val anchorHash = hex(sha256(canonical(anchor)))
        require(anchorHash.equals(expectedTrustAnchorSha256, ignoreCase = true)) { "External trust anchor mismatch" }
        require(anchor.optString("schema") == "LAEV-HUC-ANCHOR-1") { "Unknown trust anchor schema" }
        require(policy.optString("schema") == "LAEV-HUC-POLICY-1") { "Unknown policy schema" }
        ca.verify(ca.publicKey)
        require(ca.basicConstraints >= 0) { "Configured root is not a CA" }
        require(anchor.optString("ca_certificate_der_sha256") == hex(sha256(ca.encoded))) { "CA not pinned by anchor" }
        require(anchor.optString("issuer_public_key_der_sha256") == hex(sha256(issuerPublic.encoded))) { "Issuer key not pinned" }
        require(anchor.optString("policy_sha256") == hex(sha256(canonical(policy)))) { "Policy not pinned" }
        require(anchor.optString("issuer_id") == policy.optString("issuer_id")) { "Issuer mismatch" }
        require(policy.optString("consensus_mode") == "ISSUER_SIGNED_POLICY" && policy.optInt("required_signatures") == 1) { "Unsupported HUC-CC mode" }
        require(cert.issuerX500Principal == ca.subjectX500Principal) { "X.509 issuer mismatch" }
        cert.verify(ca.publicKey)
        require(cert.basicConstraints < 0) { "End-entity certificate cannot be CA" }
        val ccPayload = cc.optJSONObject("payload") ?: error("HUC-CC payload missing")
        require(cc.optString("type") == CC_TYPE && cc.optString("version") == "1") { "Unknown HUC-CC type/version" }
        require(ccPayload.optString("certificate_sha256_der") == certHash) { "HUC-CC not bound to X.509" }
        val policyHash = hex(sha256(canonical(policy)))
        require(ccPayload.optString("policy_sha256") == policyHash) { "HUC-CC policy mismatch" }
        require(ccPayload.optString("issuer_id") == policy.optString("issuer_id")) { "HUC-CC issuer mismatch" }
        require(ccPayload.optString("certificate_serial_number") == cert.serialNumber.toString()) { "HUC-CC serial mismatch" }
        val outpoint = ccPayload.optJSONObject("initial_utxo_outpoint") ?: error("HUC-CC initial output missing")
        require(outpoint.optString("txid").matches(Regex("[0-9a-f]{64}")) && outpoint.optInt("vout", -1) == 0 && ccPayload.optLong("utxo_sequence_at_issuance", -1) >= 0) { "Invalid HUC-CC UTXO reference" }
        val ccIdBody = JSONObject().put("certificate_sha256_der", certHash)
            .put("initial_utxo_outpoint", outpoint).put("policy_sha256", policyHash)
        val expectedCcId = "huc-cc:" + hex(sha256(canonical(ccIdBody)))
        require(ccPayload.optString("consensus_certificate_id") == expectedCcId) { "HUC-CC id mismatch" }
        require(ccPayload.optString("operation") == "ISSUE_OR_RENEW" && ccPayload.optString("consensus_mode") == "ISSUER_SIGNED_POLICY" && ccPayload.optInt("required_signatures") == 1) { "Invalid HUC-CC operation/policy" }
        require(ccPayload.optString("not_after_utc") == cert.notAfter.toInstant().toString()) { "HUC-CC expiry differs from X.509" }
        verifyEd25519(issuerPublic, canonical(ccPayload), Base64.getDecoder().decode(cc.optString("signature")))

        val statePayload = state.optJSONObject("payload") ?: error("State payload missing")
        require(statePayload.optString("schema") == STATE_SCHEMA) { "Unknown state attestation" }
        verifyEd25519(issuerPublic, canonical(statePayload), Base64.getDecoder().decode(state.optString("signature")))
        require(statePayload.optString("certificate_sha256_der") == certHash) { "State attestation X.509 mismatch" }
        require(statePayload.optString("consensus_certificate_sha256") == hex(sha256(canonical(cc)))) { "State attestation HUC-CC mismatch" }
        require(statePayload.optString("issuer_id") == policy.optString("issuer_id")) { "State issuer mismatch" }
        require(statePayload.optLong("ledger_event_count", 0) > 0 && statePayload.optLong("ledger_sequence", -1) >= ccPayload.optLong("utxo_sequence_at_issuance", 0)) { "Missing or invalid UTXO ledger checkpoint" }
        require(statePayload.optString("ledger_head_hash").matches(Regex("[0-9a-f]{64}"))) { "Invalid ledger checkpoint" }
        val now = Instant.now()
        val certValid = now >= cert.notBefore.toInstant() && now <= cert.notAfter.toInstant()
        require(now >= ca.notBefore.toInstant() && now <= ca.notAfter.toInstant()) { "Root CA outside validity" }
        val issuedAt = Instant.parse(statePayload.getString("issued_at_utc"))
        val expiresAt = Instant.parse(statePayload.getString("expires_at_utc"))
        val expectedTtl = policy.getJSONObject("rules").getLong("state_attestation_ttl_seconds")
        require(expectedTtl in 30..86400 && Duration.between(issuedAt, expiresAt).seconds == expectedTtl) { "State TTL differs from policy" }
        val age = Duration.between(issuedAt, now).seconds
        val fresh = age >= 0 && age <= maxStateAgeSeconds && now <= expiresAt
        val status = statePayload.optString("status")
        if (status == "ACTIVE") {
            require(canonical(statePayload.optJSONObject("utxo_outpoint") ?: JSONObject.NULL).contentEquals(canonical(outpoint))) { "Active UTXO does not match HUC-CC" }
        } else if (status == "SUPERSEDED" || status == "REVOKED") {
            require(statePayload.isNull("utxo_outpoint")) { "Consumed UTXO must not remain active" }
        } else error("Unknown UTXO status")
        val valid = certValid && fresh && status == "ACTIVE"
        val result = if (valid) "VALID" else if (!certValid || status == "SUPERSEDED" || status == "REVOKED") "INVALID" else "INDETERMINATE"
        return VerificationResult(result, valid, cert.subjectX500Principal.name, cert.serialNumber.toString(),
            certHash, status, fresh, age.coerceAtLeast(0), policy.optString("issuer_id"), anchorHash)
    }

    /** Creates a one-time relying-party challenge. Transfer it by QR/NFC/Bluetooth/HTTPS as desired. */
    fun createChallenge(certificateSha256: String, audience: String, ttlSeconds: Long = 120): JSONObject {
        require(certificateSha256.matches(Regex("[0-9a-f]{64}")))
        require(audience.isNotBlank() && audience.length <= 256)
        require(ttlSeconds in 10..300)
        val now = Instant.now().truncatedTo(ChronoUnit.SECONDS)
        val payload = JSONObject().put("schema", CHALLENGE_SCHEMA)
            .put("certificate_sha256_der", certificateSha256)
            .put("audience", audience)
            .put("nonce", ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it.toInt() and 0xff) })
            .put("created_at_utc", now.toString())
            .put("expires_at_utc", now.plusSeconds(ttlSeconds).toString())
        return JSONObject().put("payload", payload).put("challenge_id", hex(sha256(canonical(payload))))
    }

    /** Signs a challenge using an Android Keystore alias; raw private key material is never exported. */
    fun respondToChallenge(challenge: JSONObject, credentialBundle: ByteArray,
                           keystoreAlias: String): JSONObject {
        val payload = challenge.getJSONObject("payload")
        require(challenge.optString("challenge_id") == hex(sha256(canonical(payload)))) { "Challenge tampered" }
        require(payload.optString("schema") == CHALLENGE_SCHEMA) { "Unknown challenge" }
        val now = Instant.now()
        val created = Instant.parse(payload.getString("created_at_utc"))
        val expires = Instant.parse(payload.getString("expires_at_utc"))
        require(expires > created && Duration.between(created, expires).seconds <= 300 && created <= now.plusSeconds(120) && now <= expires) { "Challenge expired or not yet valid" }
        val files = unzip(credentialBundle)
        val cert = x509(files["certificate.pem"] ?: error("Certificate missing"))
        val certHash = hex(sha256(cert.encoded))
        require(certHash == payload.optString("certificate_sha256_der")) { "Challenge is for another certificate" }
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val privateKey = store.getKey(keystoreAlias, null) as? PrivateKey ?: error("Holder Keystore key not found")
        val signature = Signature.getInstance("SHA256withRSA", "AndroidKeyStore")
        signature.initSign(privateKey)
        signature.update(canonical(JSONObject().put("domain", DOMAIN).put("challenge", payload)))
        val signed = signature.sign()
        // Verify the signature against the certificate key before returning it.
        val check = Signature.getInstance("SHA256withRSA")
        check.initVerify(cert.publicKey)
        check.update(canonical(JSONObject().put("domain", DOMAIN).put("challenge", payload)))
        require(check.verify(signed)) { "Android Keystore key does not match the presented certificate" }
        return JSONObject().put("schema", RESPONSE_SCHEMA).put("challenge", challenge)
            .put("credential_bundle_b64", Base64.getEncoder().encodeToString(credentialBundle))
            .put("holder_signature_b64", Base64.getEncoder().encodeToString(signed))
            .put("responded_at_utc", Instant.now().truncatedTo(ChronoUnit.SECONDS).toString())
    }

    /** Local helper for response signature validation after server-side bundle verification. */
    fun verifyHolderSignature(certificatePem: ByteArray, challengePayload: JSONObject, signatureB64: String): Boolean {
        val cert = x509(certificatePem)
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initVerify(cert.publicKey)
        signature.update(canonical(JSONObject().put("domain", DOMAIN).put("challenge", challengePayload)))
        return signature.verify(Base64.getDecoder().decode(signatureB64))
    }

    private fun unzip(bundle: ByteArray): Map<String, ByteArray> {
        val result = mutableMapOf<String, ByteArray>()
        var total = 0
        ZipInputStream(ByteArrayInputStream(bundle)).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                require(!entry.isDirectory && !entry.name.contains("..") && !entry.name.startsWith("/")) { "Unsafe ZIP entry" }
                require(!result.containsKey(entry.name)) { "Duplicate ZIP entry" }
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                while (true) {
                    val count = zip.read(buffer)
                    if (count < 0) break
                    total += count
                    require(total <= MAX_ZIP_BYTES) { "ZIP uncompressed data too large" }
                    output.write(buffer, 0, count)
                }
                result[entry.name] = output.toByteArray()
                zip.closeEntry()
            }
        }
        return result
    }

    private fun json(files: Map<String, ByteArray>, name: String): JSONObject =
        JSONObject(String(files[name] ?: error("Missing $name"), Charsets.UTF_8))

    private fun x509(bytes: ByteArray): X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(bytes)) as X509Certificate

    private fun ed25519Public(pem: String): PublicKey {
        val parsed = PEMParser(StringReader(pem)).use { it.readObject() }
        val spki = when (parsed) {
            is org.bouncycastle.asn1.x509.SubjectPublicKeyInfo -> parsed
            else -> error("Issuer PEM is not SubjectPublicKeyInfo")
        }
        return java.security.KeyFactory.getInstance("Ed25519", "BC")
            .generatePublic(java.security.spec.X509EncodedKeySpec(spki.encoded))
    }

    private fun verifyEd25519(key: PublicKey, message: ByteArray, signatureBytes: ByteArray) {
        val signature = Signature.getInstance("Ed25519", "BC")
        signature.initVerify(key); signature.update(message)
        require(signature.verify(signatureBytes)) { "Invalid Ed25519 signature" }
    }

    private fun canonical(value: Any?): ByteArray = canonicalValue(value).toByteArray(Charsets.UTF_8)

    private fun canonicalValue(value: Any?): String = when (value) {
        null, JSONObject.NULL -> "null"
        is JSONObject -> {
            val keys = value.keys().asSequence().toList().sorted()
            keys.joinToString(prefix = "{", postfix = "}", separator = ",") { key ->
                JSONObject.quote(key) + ":" + canonicalValue(value.get(key))
            }
        }
        is JSONArray -> (0 until value.length()).joinToString(prefix = "[", postfix = "]", separator = ",") { canonicalValue(value.get(it)) }
        is String -> JSONObject.quote(value)
        is Boolean, is Int, is Long -> value.toString()
        is Number -> {
            val d = value.toDouble()
            require(d.isFinite() && d % 1.0 == 0.0) { "Protocol JSON does not permit floating point" }
            value.toLong().toString()
        }
        else -> error("Unsupported JSON value ${value::class.java.name}")
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
}
