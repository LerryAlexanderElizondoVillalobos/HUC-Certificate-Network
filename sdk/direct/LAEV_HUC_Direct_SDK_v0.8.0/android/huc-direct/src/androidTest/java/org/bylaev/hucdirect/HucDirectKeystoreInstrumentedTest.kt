package org.bylaev.hucdirect

import android.security.keystore.KeyProperties
import java.security.KeyStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import androidx.test.ext.junit.runners.AndroidJUnit4

@RunWith(AndroidJUnit4::class)
class HucDirectKeystoreInstrumentedTest {
    @Test
    fun createsNonExportableHolderKeyAndSignedCsr() {
        val alias = "huc-instrumented-${System.currentTimeMillis()}"
        try {
            val holder = HucDirectClient.createHolderKey(alias)
            assertEquals(KeyProperties.KEY_ALGORITHM_RSA, holder.publicKey.algorithm)

            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val privateKey = store.getKey(alias, null)
            assertNotNull(privateKey)
            assertNull("Android Keystore private key must not be exportable", privateKey.encoded)

            val csr = HucDirectClient.createCsr("HUC Android Instrumentation", alias)
            assertTrue(csr.contains("BEGIN CERTIFICATE REQUEST"))
            assertTrue(csr.contains("END CERTIFICATE REQUEST"))
        } finally {
            KeyStore.getInstance("AndroidKeyStore").apply {
                load(null)
                if (containsAlias(alias)) deleteEntry(alias)
            }
        }
    }
}
