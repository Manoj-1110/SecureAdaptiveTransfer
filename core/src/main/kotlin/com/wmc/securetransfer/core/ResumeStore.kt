package com.wmc.securetransfer.core

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileOutputStream

object TransferLimits {
    const val MAX_FILES = 1000
    const val MAX_FILE_BYTES = 64L * 1024 * 1024 * 1024
    const val MAX_BATCH_BYTES = 128L * 1024 * 1024 * 1024
}

/** Identity is stable across fresh sessions, and binds the full source hash and security profile. */
data class ResumeDescriptor(
    val transferId: ByteArray,
    val name: String,
    val mime: String,
    val size: Long,
    val profile: SecurityProfile,
    val contentHash: ByteArray,
) {
    internal fun encode(): ByteArray = ByteArrayOutputStream().also { buffer ->
        DataOutputStream(buffer).use {
            it.write(transferId); it.writeUTF(name); it.writeUTF(mime)
            it.writeLong(size); it.writeInt(profile.ordinal); it.write(contentHash)
        }
    }.toByteArray()
    internal val chunks get() = maxOf(1L, size / profile.chunkSize + if (size % profile.chunkSize > 0) 1 else 0)
}

interface ResumeCheckpoint {
    val verifiedChunks: Long
    val verifiedBytes: Long
    /** Reads only authenticated records, in order. The consumer must not retain the buffer. */
    fun replay(consume: (ByteArray) -> Unit)
    fun append(index: Long, plaintext: ByteArray)
    fun discard()
}

fun interface ResumeStore { fun open(descriptor: ResumeDescriptor): ResumeCheckpoint }

/**
 * Private, encrypted chunk journal. There is no trusted plaintext offset or mutable manifest:
 * every restart authenticates the immutable descriptor and every contiguous saved chunk.
 * The caller supplies a 256-bit local key (Android wraps it using Android Keystore).
 * Each record uses a fresh 256-bit salt to derive an independent AES key; its nonce is zero.
 * A record is synced and atomically renamed before it is counted as verified.
 */
class EncryptedResumeStore(
    private val root: File,
    secret: ByteArray,
    private val maxBytes: Long = 8L * 1024 * 1024 * 1024,
    private val expiryMillis: Long = 24L * 60 * 60 * 1000,
) : ResumeStore, AutoCloseable {
    private val key = secret.copyOf().also { require(it.size == 32) }
    private var usedBytes = 0L

    init {
        require(maxBytes > 0 && expiryMillis > 0); check(root.mkdirs() || root.isDirectory)
        usedBytes = root.walkTopDown().filter { it.isFile }.sumOf { it.length() }
    }

    @Synchronized fun cleanup(now: Long = System.currentTimeMillis()) {
        root.listFiles()?.forEach { dir ->
            if (now - dir.lastModified() > expiryMillis) dir.deleteRecursively()
        }
        usedBytes = root.walkTopDown().filter { it.isFile }.sumOf { it.length() }
    }

    @Synchronized fun clear() { root.listFiles()?.forEach { it.deleteRecursively() }; usedBytes = 0L }

    @Synchronized override fun open(descriptor: ResumeDescriptor): ResumeCheckpoint {
        require(descriptor.transferId.size == 16 && descriptor.contentHash.size == 32)
        require(descriptor.size in 0..TransferLimits.MAX_FILE_BYTES)
        cleanup()
        val id = descriptor.transferId.joinToString("") { "%02x".format(it.toInt() and 255) }
        val dir = File(root, id)
        val identity = descriptor.encode()
        val aad = Crypto.sha256(identity)
        val meta = File(dir, "identity")
        try {
            if (meta.exists()) {
                val existing = decrypt(meta, "$id/identity", aad, 2048)
                try {
                    if (!Crypto.constantTimeEquals(existing, identity)) throw IntegrityException("Resume identity changed")
                } finally { Crypto.wipe(existing) }
            } else {
                if ((root.listFiles()?.size ?: 0) >= TransferLimits.MAX_FILES)
                    throw ProtocolException("Too many partial transfers; clear saved partial files")
                check(dir.mkdirs() || dir.isDirectory)
                writeRecord(meta, "$id/identity", aad, identity)
            }
            return Journal(dir, id, descriptor, aad).also { it.validate() }
        } catch (e: Exception) {
            dir.deleteRecursively()
            throw e
        }
    }

    private inner class Journal(
        val dir: File, val id: String, val descriptor: ResumeDescriptor, val aad: ByteArray,
    ) : ResumeCheckpoint {
        override var verifiedChunks: Long = 0; private set
        override val verifiedBytes get() = minOf(descriptor.size, verifiedChunks * descriptor.profile.chunkSize)
        private fun chunk(index: Long) = File(dir, "$index.chunk")
        private fun expected(index: Long) = minOf(descriptor.profile.chunkSize.toLong(),
            descriptor.size - index * descriptor.profile.chunkSize).toInt()

        fun validate() {
            while (verifiedChunks < descriptor.chunks && chunk(verifiedChunks).exists()) {
                val pt = read(verifiedChunks)
                Crypto.wipe(pt)
                verifiedChunks++
            }
            // An interrupted atomic write is not a checkpoint.
            dir.listFiles()?.filter { it.name.endsWith(".tmp") }?.forEach { it.delete() }
            dir.setLastModified(System.currentTimeMillis())
        }

        private fun read(index: Long): ByteArray {
            val pt = decrypt(chunk(index), "$id/$index", aad, descriptor.profile.chunkSize)
            if (pt.size != expected(index)) { Crypto.wipe(pt); throw IntegrityException("Invalid saved chunk length") }
            return pt
        }

        override fun replay(consume: (ByteArray) -> Unit) {
            for (index in 0 until verifiedChunks) {
                val pt = read(index)
                try { consume(pt) } finally { Crypto.wipe(pt) }
            }
        }

        override fun append(index: Long, plaintext: ByteArray) {
            if (index != verifiedChunks || index >= descriptor.chunks || plaintext.size != expected(index))
                throw IntegrityException("Invalid checkpoint sequence")
            synchronized(this@EncryptedResumeStore) {
                if (usedBytes + plaintext.size + 48 > maxBytes || root.usableSpace < plaintext.size + 4L * 1024 * 1024)
                    throw ProtocolException("Private transfer storage is full; clear partial files or free space")
                writeRecord(chunk(index), "$id/$index", aad, plaintext)
                verifiedChunks++
                dir.setLastModified(System.currentTimeMillis())
            }
        }

        override fun discard() { synchronized(this@EncryptedResumeStore) {
            val previousBytes = dir.walkTopDown().filter { it.isFile }.sumOf { it.length() }
            if (dir.deleteRecursively()) usedBytes = (usedBytes - previousBytes).coerceAtLeast(0)
        } }
    }

    private fun writeRecord(target: File, label: String, aad: ByteArray, plain: ByteArray) {
        val salt = Crypto.random(32)
        val recordKey = Crypto.hkdf(key, salt, "SAT/local/$label")
        val encrypted = try { Crypto.gcmEncrypt(recordKey, ByteArray(12), aad, plain) }
            finally { Crypto.wipe(recordKey) }
        val tmp = File(target.parentFile, target.name + ".tmp")
        val previousLength = target.length()
        FileOutputStream(tmp).use { it.write(salt); it.write(encrypted); it.fd.sync() }
        if (!tmp.renameTo(target)) { tmp.delete(); throw java.io.IOException("Could not persist checkpoint") }
        usedBytes += target.length() - previousLength
    }

    private fun decrypt(file: File, label: String, aad: ByteArray, maxPlain: Int): ByteArray {
        if (file.length() !in 48L..maxPlain.toLong() + 48) throw IntegrityException("Invalid checkpoint record size")
        val record = file.readBytes()
        val recordKey = Crypto.hkdf(key, record.copyOfRange(0, 32), "SAT/local/$label")
        return try { Crypto.gcmDecrypt(recordKey, ByteArray(12), aad, record.copyOfRange(32, record.size)) }
            finally { Crypto.wipe(recordKey, record) }
    }

    override fun close() { Crypto.wipe(key) }
}
