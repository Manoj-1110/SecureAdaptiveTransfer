package com.wmc.securetransfer.core

import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.security.interfaces.ECPublicKey
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class ProtocolException(message: String, cause: Throwable? = null) : Exception(message, cause)
class IntegrityException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** Thin wrappers over the Java Cryptography Architecture (available on Android and the JVM). */
object Crypto {
    const val KEY_BYTES = 32          // AES-256
    const val IV_BYTES = 12           // 96-bit GCM nonce
    const val TAG_BITS = 128          // 128-bit authentication tag
    const val TAG_BYTES = TAG_BITS / 8
    const val PBKDF2_ITERATIONS = 600_000

    private val rng = SecureRandom()

    fun random(n: Int): ByteArray = ByteArray(n).also { rng.nextBytes(it) }

    fun sha256(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        parts.forEach { md.update(it) }
        return md.digest()
    }

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /** HKDF-SHA256 (RFC 5869). */
    fun hkdf(ikm: ByteArray, salt: ByteArray?, info: String, length: Int = KEY_BYTES): ByteArray =
        hkdf(ikm, salt, info.toByteArray(Charsets.UTF_8), length)

    fun hkdf(ikm: ByteArray, salt: ByteArray?, infoBytes: ByteArray, length: Int): ByteArray {
        require(length in 1..255 * 32)
        val prk = hmacSha256(if (salt == null || salt.isEmpty()) ByteArray(32) else salt, ikm)
        val out = ByteArray(length)
        var t = ByteArray(0)
        var pos = 0
        var counter = 1
        while (pos < length) {
            val previous = t
            t = hmacSha256(prk, previous + infoBytes + byteArrayOf(counter.toByte()))
            wipe(previous)
            val n = minOf(t.size, length - pos)
            System.arraycopy(t, 0, out, pos, n)
            pos += n
            counter++
        }
        wipe(prk, t)
        return out
    }

    fun pbkdf2(password: CharArray, salt: ByteArray, iterations: Int = PBKDF2_ITERATIONS): ByteArray {
        require(iterations == PBKDF2_ITERATIONS) { "Unsupported password work factor" }
        require(salt.size == 16) { "Invalid password salt" }
        val spec = PBEKeySpec(password, salt, iterations, KEY_BYTES * 8)
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }

    fun gcmEncrypt(key: ByteArray, iv: ByteArray, aad: ByteArray, plaintext: ByteArray, len: Int = plaintext.size): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
        c.updateAAD(aad)
        return c.doFinal(plaintext, 0, len)
    }

    fun gcmDecrypt(key: ByteArray, iv: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
        c.updateAAD(aad)
        try {
            return c.doFinal(ciphertext)
        } catch (e: AEADBadTagException) {
            throw IntegrityException("Authentication tag check failed (data tampered or wrong key)", e)
        }
    }

    /** 96-bit nonce = 4-byte domain + 8-byte counter. Unique per key by construction. */
    fun nonce(domain: Int, counter: Long): ByteArray =
        ByteBuffer.allocate(IV_BYTES).putInt(domain).putLong(counter).array()

    fun constantTimeEquals(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)

    fun wipe(vararg arrays: ByteArray?) = arrays.forEach { it?.fill(0) }
}

/** Ephemeral ECDH on NIST P-256 – keys never leave the device; only public halves are exchanged. */
object KeyExchange {
    fun generate(): KeyPair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    fun decodePublic(encoded: ByteArray): PublicKey =
        try {
            val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(encoded)) as ECPublicKey
            val expected = (generate().public as ECPublicKey).params
            if (key.params.curve != expected.curve || key.params.generator != expected.generator ||
                key.params.order != expected.order || key.params.cofactor != expected.cofactor)
                throw ProtocolException("Peer key must use P-256")
            key
        } catch (e: Exception) {
            throw ProtocolException("Peer sent an invalid public key", e)
        }

    fun agree(priv: PrivateKey, peer: PublicKey): ByteArray =
        KeyAgreement.getInstance("ECDH").apply { init(priv); doPhase(peer, true) }.generateSecret()
}
