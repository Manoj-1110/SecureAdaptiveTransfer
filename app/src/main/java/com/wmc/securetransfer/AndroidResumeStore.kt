package com.wmc.securetransfer

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import android.util.Log
import com.wmc.securetransfer.core.Crypto
import com.wmc.securetransfer.core.EncryptedResumeStore
import java.io.File
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Only a wrapped checkpoint key is stored; its Android Keystore wrapping key is non-exportable. */
object AndroidResumeStore {
    /** Serialize key creation and AtomicFile access; concurrent initialization must never replace an alias. */
    @Synchronized fun create(context: Context, onReset: (String) -> Unit = {}): EncryptedResumeStore {
        val keystore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = "secure_transfer_resume_v2"
        val file = AtomicFile(File(context.noBackupFilesDir, "resume-key-v2"))
        val root = File(context.noBackupFilesDir, "resume-v2")
        val aad = "SecureTransfer/local-key/v2".toByteArray()
        var wrapKey = keystore.getKey(alias, null) as? SecretKey

        fun reset(reason: String) {
            // Unreadable records are never reused or treated as authenticated resumable data.
            check(!root.exists() || root.deleteRecursively()) { "Could not discard invalid recovery state" }
            file.delete()
            if (keystore.containsAlias(alias)) keystore.deleteEntry(alias)
            wrapKey = null
            val message = "Saved partial transfers were discarded: $reason. Retry from the original files."
            Log.w("SecureTransfer", message)
            onReset(message)
        }
        if (wrapKey == null && file.baseFile.exists()) reset("the local Keystore key is no longer available")
        var secret: ByteArray? = null
        if (wrapKey != null && file.baseFile.exists()) {
            val record = ByteArray(60)
            var valid = true
            try {
                java.io.DataInputStream(file.openRead()).use { input ->
                    input.readFully(record)
                    if (input.read() != -1) valid = false
                }
            } catch (_: java.io.EOFException) { valid = false }
            if (!valid) { Crypto.wipe(record); reset("the encrypted local key record is invalid") }
            else {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, wrapKey, GCMParameterSpec(128, record.copyOfRange(0, 12)))
                cipher.updateAAD(aad)
                try { secret = cipher.doFinal(record, 12, record.size - 12) }
                catch (_: AEADBadTagException) { reset("the local recovery-key authentication failed") }
                finally { Crypto.wipe(record) }
            }
        }
        if (secret == null) {
            if (wrapKey == null) wrapKey = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
                init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256).build())
            }.generateKey()
            val bytes = Crypto.random(32)
            try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, wrapKey)
                cipher.updateAAD(aad)
                val encrypted = cipher.doFinal(bytes)
                val output = file.startWrite()
                try { output.write(cipher.iv); output.write(encrypted); file.finishWrite(output) }
                catch (e: Exception) { file.failWrite(output); throw e }
                secret = bytes
            } catch (e: Exception) { Crypto.wipe(bytes); throw e }
        }
        val key = checkNotNull(secret)
        return try { EncryptedResumeStore(root, key) } finally { Crypto.wipe(key) }
    }
}
