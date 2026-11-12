package org.bylaev.hucdirect

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.Base64
import java.util.concurrent.TimeUnit

/**
 * Optional adapter for the HUC Direct REST API.
 * Calls are synchronous: invoke from Dispatchers.IO, an Executor or WorkManager,
 * never from Android's main/UI thread.
 */
class HucDirectApiClient(
    baseUrl: String,
    private val http: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .writeTimeout(20, TimeUnit.SECONDS)
        .build()
) {
    private val base = baseUrl.trimEnd('/')
    private val jsonType = "application/json; charset=utf-8".toMediaType()

    init {
        require(base.startsWith("https://") || base.startsWith("http://10.0.2.2") || base.startsWith("http://127.0.0.1")) {
            "Use HTTPS except for Android emulator/local development"
        }
    }

    fun verifyBundle(bundle: ByteArray): JSONObject {
        val body = JSONObject().put("bundle_b64", Base64.getEncoder().encodeToString(bundle))
        return post("/v1/credentials/verify", body)
    }

    fun createChallenge(certificateSha256: String, audience: String, ttlSeconds: Int = 120): JSONObject {
        val body = JSONObject().put("certificate_sha256", certificateSha256)
            .put("audience", audience).put("ttl_seconds", ttlSeconds)
        return post("/v1/direct/challenges", body)
    }

    fun verifyDirect(challenge: JSONObject, response: JSONObject, audience: String): JSONObject {
        val body = JSONObject().put("challenge", challenge).put("response", response).put("audience", audience)
        return post("/v1/direct/verify", body)
    }


    private fun post(path: String, body: JSONObject): JSONObject {
        val request = Request.Builder().url(base + path)
            .post(body.toString().toRequestBody(jsonType)).build()
        http.newCall(request).execute().use { response ->
            val text = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                val detail = runCatching { JSONObject(text).optString("detail", text) }.getOrDefault(text)
                throw IllegalStateException("HUC API ${response.code}: $detail")
            }
            return JSONObject(text)
        }
    }
}
