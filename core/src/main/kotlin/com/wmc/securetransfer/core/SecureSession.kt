package com.wmc.securetransfer.core

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.nio.ByteBuffer
import java.util.Locale

/**
 * Wire protocol "SAT2" (Secure Adaptive Transfer, version 2).
 *
 * Handshake (public values only): commit to SHA-256(public key, nonce), then reveal.
 *   each side → "SAT2" | version | commitment, then ECDH P-256 public key | 32-byte nonce
 *   master = HKDF(ECDH secret, salt = SHA-256(transcript), "SAT/master")
 *   SAS    = 6-digit code from HKDF(master, "SAT/sas") shown on both screens
 *            so users can detect a man-in-the-middle.
 *
 * After the handshake every frame is:  type(1) | length(4) | AES-256-GCM ciphertext+tag
 * Control frames use one key per direction with counter nonces.
 * Chunk frames use the data keys chosen by the file's [SecurityProfile].
 */
internal object Wire {
    val MAGIC = "SAT2".toByteArray(Charsets.US_ASCII)
    const val VERSION = 2
    const val NONCE_BYTES = 32
    const val MAX_PUBKEY = 512
    const val MAX_FRAME = 1024 * 1024 + 4096

    const val T_FILE_HEADER = 1
    const val T_CHUNK = 2
    const val T_FILE_TRAILER = 3
    const val T_END = 4
    const val T_ACK = 5
    const val T_CONFIRM = 6
    const val T_RESUME = 7
    const val T_FILE_VERIFIED = 8
    const val T_RECEIPT = 9

    const val ACK_OK = 0
    const val ACK_REJECT_PASSWORD = 1
    const val ACK_HASH_MISMATCH = 2
    const val ACK_DECLINED = 3

    fun writeBlob(out: DataOutputStream, b: ByteArray) { out.writeInt(b.size); out.write(b) }

    fun readBlob(inp: DataInputStream, max: Int): ByteArray {
        val n = inp.readInt()
        if (n < 0 || n > max) throw ProtocolException("Frame length $n out of range")
        return ByteArray(n).also { inp.readFully(it) }
    }
}

class SecureSession private constructor(
    val isSender: Boolean,
    internal val master: ByteArray,
    /** Short authentication string: compare on both phones. */
    val verificationCode: String,
    private val inp: DataInputStream,
    private val out: DataOutputStream,
) : AutoCloseable {

    private val keyS2R = Crypto.hkdf(master, null, "SAT/control/s2r")
    private val keyR2S = Crypto.hkdf(master, null, "SAT/control/r2s")
    private val txKey get() = if (isSender) keyS2R else keyR2S
    private val rxKey get() = if (isSender) keyR2S else keyS2R
    private var txCounter = 0L
    private var rxCounter = 0L

    /** Session-wide data key used by the Standard profile. */
    internal val sessionDataKey: ByteArray = Crypto.hkdf(master, null, "SAT/data/session")

    // Control domain ids keep control nonces disjoint from each other.
    private val txDomain get() = if (isSender) 0x5332_5200 else 0x5232_5300
    private val rxDomain get() = if (isSender) 0x5232_5300 else 0x5332_5200

    internal fun sendControl(type: Int, payload: ByteArray) {
        if (txCounter == Long.MAX_VALUE) throw ProtocolException("Session counter exhausted")
        if (payload.size > Wire.MAX_FRAME - Crypto.TAG_BYTES) throw ProtocolException("Control frame too large")
        val ct = Crypto.gcmEncrypt(txKey, Crypto.nonce(txDomain, txCounter++), byteArrayOf(type.toByte()), payload)
        out.writeByte(type)
        Wire.writeBlob(out, ct)
        out.flush()
    }

    /** Reads the next frame; control frames are decrypted, chunk frames returned raw. */
    internal fun readFrame(): Pair<Int, ByteArray> {
        val type = try { inp.readUnsignedByte() } catch (e: EOFException) {
            throw ProtocolException("Connection closed by peer", e)
        }
        val body = Wire.readBlob(inp, Wire.MAX_FRAME)
        if (type == Wire.T_CHUNK) return type to body
        if (type !in Wire.T_FILE_HEADER..Wire.T_RECEIPT || rxCounter == Long.MAX_VALUE)
            throw ProtocolException("Invalid control frame")
        val pt = Crypto.gcmDecrypt(rxKey, Crypto.nonce(rxDomain, rxCounter++), byteArrayOf(type.toByte()), body)
        return type to pt
    }

    internal fun expectControl(expected: Int): ByteArray {
        val (type, body) = readFrame()
        if (type != expected) throw ProtocolException("Expected frame $expected but got $type")
        return body
    }

    internal fun sendChunk(ciphertext: ByteArray) {
        out.writeByte(Wire.T_CHUNK)
        Wire.writeBlob(out, ciphertext)
    }

    internal fun flush() = out.flush()

    /** Fail closed. Both endpoints must explicitly accept the same SAS before metadata or data. */
    internal fun confirm(listener: TransferListener) {
        listener.onVerificationCode(verificationCode)
        val accepted = listener.confirmVerification(verificationCode)
        sendControl(Wire.T_CONFIRM, byteArrayOf(if (accepted) 1 else 0))
        if (!accepted) throw ProtocolException("Authentication code rejected locally")
        val peer = expectControl(Wire.T_CONFIRM)
        if (!peer.contentEquals(byteArrayOf(1))) throw ProtocolException("Peer rejected the authentication code")
        listener.onLog("Both users confirmed the authentication code")
    }

    internal fun expectAck() {
        val ack = expectControl(Wire.T_ACK)
        if (!ack.contentEquals(byteArrayOf(Wire.ACK_OK.toByte())))
            throw ProtocolException("Peer rejected the transfer")
    }

    override fun close() {
        Crypto.wipe(master, keyS2R, keyR2S, sessionDataKey)
    }

    companion object {
        fun handshake(inp: DataInputStream, out: DataOutputStream, isSender: Boolean): SecureSession {
            val kp = KeyExchange.generate()
            val myPub = kp.public.encoded
            val myNonce = Crypto.random(Wire.NONCE_BYTES)

            // Commit before revealing either random hello. This prevents an active peer from
            // grinding its final nonce to force a chosen six-digit SAS after learning ours.
            val commitment = Crypto.sha256(Wire.MAGIC, byteArrayOf(Wire.VERSION.toByte()), myPub, myNonce)
            fun sendCommitment() {
                out.write(Wire.MAGIC); out.writeByte(Wire.VERSION)
                Wire.writeBlob(out, commitment); out.flush()
            }
            fun readCommitment(): ByteArray {
                val magic = ByteArray(4).also { inp.readFully(it) }
                if (!magic.contentEquals(Wire.MAGIC)) throw ProtocolException("Peer is not a compatible Secure Adaptive Transfer app")
                if (inp.readUnsignedByte() != Wire.VERSION) throw ProtocolException("Both phones must use protocol version ${Wire.VERSION}")
                return Wire.readBlob(inp, 32).also {
                    if (it.size != 32) throw ProtocolException("Invalid handshake commitment")
                }
            }
            val peerCommitment = if (isSender) {
                sendCommitment(); readCommitment()
            } else readCommitment().also { sendCommitment() }
            fun sendHello() { Wire.writeBlob(out, myPub); out.write(myNonce); out.flush() }
            fun readHello(): Pair<ByteArray, ByteArray> {
                val pub = Wire.readBlob(inp, Wire.MAX_PUBKEY)
                val nonce = ByteArray(Wire.NONCE_BYTES).also { inp.readFully(it) }
                if (!Crypto.constantTimeEquals(peerCommitment,
                        Crypto.sha256(Wire.MAGIC, byteArrayOf(Wire.VERSION.toByte()), pub, nonce)))
                    throw IntegrityException("Handshake commitment did not match the revealed key")
                return pub to nonce
            }
            val (peerPub, peerNonce) = if (isSender) {
                sendHello(); readHello()
            } else readHello().also { sendHello() }
            if (peerPub.contentEquals(myPub)) throw ProtocolException("Reflected handshake detected")

            val shared = KeyExchange.agree(kp.private, KeyExchange.decodePublic(peerPub))
            val (sPub, rPub) = if (isSender) myPub to peerPub else peerPub to myPub
            val (sNonce, rNonce) = if (isSender) myNonce to peerNonce else peerNonce to myNonce
            val transcript = Crypto.sha256(Wire.MAGIC, byteArrayOf(Wire.VERSION.toByte()), sPub, rPub, sNonce, rNonce)

            val master = Crypto.hkdf(shared, transcript, "SAT/master")
            Crypto.wipe(shared)
            val sasBytes = Crypto.hkdf(master, transcript, "SAT/sas", 4)
            val sas = (ByteBuffer.wrap(sasBytes).int.toLong() and 0xFFFF_FFFFL) % 1_000_000
            val code = String.format(Locale.US, "%03d %03d", sas / 1000, sas % 1000)
            return SecureSession(isSender, master, code, inp, out)
        }
    }
}

/** Metadata sent (encrypted) before each file. */
internal data class FileHeader(
    val fileIndex: Int,
    val totalFiles: Int,
    val fileId: ByteArray,
    val name: String,
    val mimeType: String,
    val size: Long,
    val profile: SecurityProfile,
    val chunkSize: Int,
    val passwordSalt: ByteArray,
    val pbkdf2Iterations: Int,
    val passwordCheck: ByteArray,
    val transferId: ByteArray,
    val contentHash: ByteArray,
) {
    val chunkCount: Long get() = maxOf(1L, size / chunkSize + if (size % chunkSize > 0) 1 else 0)

    fun encode(): ByteArray = ByteArrayOutputStream().also { bos ->
        DataOutputStream(bos).apply {
            writeInt(fileIndex); writeInt(totalFiles)
            Wire.writeBlob(this, fileId)
            writeUTF(name); writeUTF(mimeType); writeLong(size)
            writeByte(profile.ordinal); writeInt(chunkSize)
            Wire.writeBlob(this, passwordSalt); writeInt(pbkdf2Iterations)
            Wire.writeBlob(this, passwordCheck)
            Wire.writeBlob(this, transferId); Wire.writeBlob(this, contentHash)
            flush()
        }
    }.toByteArray()

    companion object {
        fun decode(b: ByteArray): FileHeader {
            val d = DataInputStream(b.inputStream())
            val h = FileHeader(
                fileIndex = d.readInt(), totalFiles = d.readInt(),
                fileId = Wire.readBlob(d, 64),
                name = d.readUTF(), mimeType = d.readUTF(), size = d.readLong(),
                profile = SecurityProfile.fromId(d.readUnsignedByte()), chunkSize = d.readInt(),
                passwordSalt = Wire.readBlob(d, 64), pbkdf2Iterations = d.readInt(),
                passwordCheck = Wire.readBlob(d, 64),
                transferId = Wire.readBlob(d, 16), contentHash = Wire.readBlob(d, 32),
            )
            if (d.available() != 0) throw ProtocolException("Trailing metadata")
            if (h.size !in 0..TransferLimits.MAX_FILE_BYTES) throw ProtocolException("Unsupported file size")
            if (h.totalFiles !in 1..TransferLimits.MAX_FILES || h.fileIndex !in 0 until h.totalFiles)
                throw ProtocolException("Invalid file count or index")
            if (h.name.isBlank() || h.name.length > 240 || h.mimeType.length > 128 ||
                h.mimeType.any { it.isISOControl() }) throw ProtocolException("Invalid file metadata")
            if (h.transferId.size != 16 || h.contentHash.size != 32) throw ProtocolException("Invalid resume identity")
            if (ContextAnalyzer.classify(FileFacts(h.name, h.mimeType, h.size)) == Sensitivity.SENSITIVE &&
                h.profile != SecurityProfile.MAXIMUM) throw ProtocolException("Sensitive file requires Maximum protection")
            if (h.chunkSize != h.profile.chunkSize) throw ProtocolException("Chunk size does not match profile")
            if (h.fileId.size != 16) throw ProtocolException("Bad file id")
            if (h.profile.requiresPassword && (h.passwordSalt.size != 16 || h.pbkdf2Iterations != Crypto.PBKDF2_ITERATIONS || h.passwordCheck.size != 16))
                throw ProtocolException("Invalid password parameters")
            if (!h.profile.requiresPassword && (h.passwordSalt.isNotEmpty() || h.pbkdf2Iterations != 0 || h.passwordCheck.isNotEmpty()))
                throw ProtocolException("Unexpected password parameters")
            return h
        }
    }
}

/** Derives the AES-256 keys for a file according to its profile's rotation policy. */
internal class FileKeys(session: SecureSession, h: FileHeader, passwordKey: ByteArray?) : AutoCloseable {
    private val fileKey: ByteArray = when (h.profile.rotation) {
        KeyRotation.PER_SESSION -> session.sessionDataKey.copyOf()
        KeyRotation.PER_FILE -> Crypto.hkdf(session.master, h.fileId, "SAT/data/file")
        KeyRotation.PER_CHUNK -> {
            requireNotNull(passwordKey) { "Password key required" }
            val combined = session.master + passwordKey
            try { Crypto.hkdf(combined, h.fileId, "SAT/data/file+password") } finally { Crypto.wipe(combined) }
        }
    }
    private val perChunk = h.profile.rotation == KeyRotation.PER_CHUNK

    val passwordCheck: ByteArray =
        if (perChunk) Crypto.hkdf(fileKey, null, "SAT/password-check", 16) else ByteArray(0)

    fun keyFor(chunk: Long): ByteArray =
        if (perChunk) Crypto.hkdf(fileKey, null, "SAT/chunk/$chunk") else fileKey

    override fun close() = Crypto.wipe(fileKey, passwordCheck)
}

internal fun chunkAad(fileId: ByteArray, index: Long, last: Boolean): ByteArray =
    ByteBuffer.allocate(fileId.size + 9).put(fileId).putLong(index).put(if (last) 1 else 0).array()
