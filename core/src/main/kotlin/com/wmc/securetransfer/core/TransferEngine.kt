package com.wmc.securetransfer.core

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.security.MessageDigest
import java.util.concurrent.CancellationException

/** Streams must be reopenable and immutable throughout hashing, sending and retry. */
class OutgoingFile(
    val name: String,
    val mimeType: String,
    val size: Long,
    val profile: SecurityProfile,
    val transferId: ByteArray = Crypto.random(16),
    val open: () -> InputStream,
)

interface IncomingSink {
    val output: OutputStream
    /** Publish only verified data. Must throw if publication fails. */
    fun commit(): String
    fun finishWriting() { output.flush() }
    fun abort()
}
fun interface SinkFactory { fun create(name: String, mimeType: String, size: Long): IncomingSink }
fun interface PasswordProvider { fun request(fileName: String, attempt: Int): CharArray? }

interface TransferListener {
    fun onVerificationCode(code: String) {}
    /** Platform UI must obtain an explicit user decision. The default rejects unattended transfers. */
    fun confirmVerification(code: String): Boolean = false
    fun isCancelled(): Boolean = Thread.currentThread().isInterrupted
    fun onFileStarted(index: Int, total: Int, name: String, profile: SecurityProfile, size: Long) {}
    fun onProgress(index: Int, bytesDone: Long, size: Long) {}
    fun onFileFinished(index: Int, name: String, location: String?) {}
    fun onLog(message: String) {}
}
data class TransferResult(val files: List<String>, val bytes: Long, val millis: Long)

object TransferEngine {
    const val DEFAULT_PORT = 8988
    private const val MAX_PASSWORD_ATTEMPTS = 3
    private fun checkCancelled(listener: TransferListener) {
        if (listener.isCancelled()) throw CancellationException("Transfer cancelled")
    }
    fun streams(socket: Socket): Pair<DataInputStream, DataOutputStream> =
        DataInputStream(BufferedInputStream(socket.getInputStream(), 64 * 1024)) to
            DataOutputStream(BufferedOutputStream(socket.getOutputStream(), 64 * 1024))

    fun send(
        inp: DataInputStream, out: DataOutputStream, files: List<OutgoingFile>, password: CharArray?,
        listener: TransferListener = object : TransferListener {},
    ): TransferResult {
        require(files.size in 1..TransferLimits.MAX_FILES) { "Choose 1–${TransferLimits.MAX_FILES} files" }
        require(files.all { it.size in 0..TransferLimits.MAX_FILE_BYTES && it.transferId.size == 16 }) { "Invalid file size or identity" }
        require(files.sumOf { it.size } <= TransferLimits.MAX_BATCH_BYTES) { "Batch is too large" }
        require(files.map { it.transferId.toList() }.distinct().size == files.size) { "Duplicate transfer identity" }
        files.forEach {
            require(ContextAnalyzer.classify(FileFacts(it.name, it.mimeType, it.size)) != Sensitivity.SENSITIVE ||
                it.profile == SecurityProfile.MAXIMUM) { "Sensitive files require Maximum protection" }
            require(it.name.isNotBlank() && it.name.length <= 240 && it.mimeType.length <= 128) { "Invalid file metadata" }
        }
        if (files.any { it.profile.requiresPassword } && (password == null || password.size !in 8..1024))
            throw IllegalArgumentException("Maximum profile needs a password of 8–1024 characters")
        val start = System.nanoTime()
        val batchHash = MessageDigest.getInstance("SHA-256")
        var totalBytes = 0L
        SecureSession.handshake(inp, out, true).use { session ->
            session.confirm(listener)
            files.forEachIndexed { index, file ->
                checkCancelled(listener)
                listener.onFileStarted(index, files.size, file.name, file.profile, file.size)
                listener.onLog("Checking source integrity: ${file.name}")
                val sourceHash = hashSource(file, listener)
                val salt = if (file.profile.requiresPassword) Crypto.random(16) else ByteArray(0)
                val pwKey = if (file.profile.requiresPassword) Crypto.pbkdf2(password!!, salt) else null
                val base = FileHeader(index, files.size, Crypto.random(16), file.name, file.mimeType, file.size,
                    file.profile, file.profile.chunkSize, salt, if (pwKey != null) Crypto.PBKDF2_ITERATIONS else 0,
                    ByteArray(0), file.transferId, sourceHash)
                val fileKeys = try { FileKeys(session, base, pwKey) } finally { Crypto.wipe(pwKey) }
                fileKeys.use { keys ->
                    val header = base.copy(passwordCheck = keys.passwordCheck)
                    val encoded = header.encode()
                    batchHash.update(encoded)
                    session.sendControl(Wire.T_FILE_HEADER, encoded)
                    session.expectAck()
                    val resume = DataInputStream(session.expectControl(Wire.T_RESUME).inputStream())
                    val offset = resume.readLong()
                    val prefixHash = ByteArray(32).also { resume.readFully(it) }
                    if (resume.available() != 0 || offset !in 0..header.chunkCount)
                        throw ProtocolException("Invalid resume offset")
                    val digest = MessageDigest.getInstance("SHA-256")
                    val prefixDigest = MessageDigest.getInstance("SHA-256")
                    val buffer = ByteArray(header.chunkSize)
                    var done = 0L
                    try {
                        file.open().use { source ->
                            // Rehash the prefix against the authenticated offer; never blindly seek.
                            for (chunk in 0 until offset) {
                                checkCancelled(listener)
                                val want = minOf(buffer.size.toLong(), file.size - done).toInt()
                                readExact(source, buffer, want)
                                digest.update(buffer, 0, want); prefixDigest.update(buffer, 0, want)
                                done += want
                            }
                            if (!Crypto.constantTimeEquals(prefixDigest.digest(), prefixHash))
                                throw IntegrityException("Saved prefix does not match the selected source")
                            if (offset > 0) listener.onLog("Resuming ${file.name} from ${ContextAnalyzer.formatBytes(done)} using fresh session keys")
                            listener.onProgress(index, done, file.size)
                            for (chunk in offset until header.chunkCount) {
                                checkCancelled(listener)
                                val want = minOf(buffer.size.toLong(), file.size - done).toInt()
                                readExact(source, buffer, want)
                                digest.update(buffer, 0, want)
                                val key = keys.keyFor(chunk)
                                val ct = try { Crypto.gcmEncrypt(key, Crypto.nonce(index, chunk),
                                    chunkAad(header.fileId, chunk, chunk == header.chunkCount - 1), buffer, want) }
                                    finally { if (file.profile.rotation == KeyRotation.PER_CHUNK) Crypto.wipe(key) }
                                session.sendChunk(ct)
                                session.flush()
                                done += want
                                listener.onProgress(index, done, file.size)
                            }
                            if (source.read() != -1) throw IntegrityException("Source grew during transfer")
                        }
                        val actual = digest.digest()
                        if (!Crypto.constantTimeEquals(sourceHash, actual)) throw IntegrityException("Source changed during transfer; retry with the original file")
                        batchHash.update(actual)
                        session.sendControl(Wire.T_FILE_TRAILER, actual)
                        val verified = session.expectControl(Wire.T_FILE_VERIFIED)
                        if (!Crypto.constantTimeEquals(verified, actual)) throw IntegrityException("Receiver did not verify this file")
                        listener.onLog("${file.name}: authenticated and staged on receiver")
                        totalBytes += file.size
                    } finally { Crypto.wipe(buffer) }
                }
            }
            val completion = completion(files.size, totalBytes, batchHash.digest())
            session.sendControl(Wire.T_END, completion)
            if (!Crypto.constantTimeEquals(session.expectControl(Wire.T_RECEIPT), completion))
                throw IntegrityException("Invalid transfer completion receipt")
            files.forEachIndexed { index, f -> listener.onFileFinished(index, f.name, null) }
        }
        return TransferResult(files.map { it.name }, totalBytes, (System.nanoTime() - start) / 1_000_000)
    }

    fun receive(
        inp: DataInputStream, out: DataOutputStream, sinks: SinkFactory, passwords: PasswordProvider,
        listener: TransferListener = object : TransferListener {}, resumeStore: ResumeStore? = null,
    ): TransferResult {
        data class Pending(val header: FileHeader, val sink: IncomingSink, val checkpoint: ResumeCheckpoint?)
        val start = System.nanoTime()
        var cachedPassword: CharArray? = null
        val pending = mutableListOf<Pending>()
        var currentCheckpoint: ResumeCheckpoint? = null
        var currentSink: IncomingSink? = null
        val saved = mutableListOf<String>()
        var totalBytes = 0L
        var complete = false
        var preserve = false
        try {
            SecureSession.handshake(inp, out, false).use { session ->
                session.confirm(listener)
                val batchHash = MessageDigest.getInstance("SHA-256")
                var declaredCount: Int? = null
                val identities = mutableSetOf<List<Byte>>()
                while (true) {
                    checkCancelled(listener)
                    val (type, body) = session.readFrame()
                    if (type == Wire.T_END) {
                        if (declaredCount == null || pending.size != declaredCount)
                            throw ProtocolException("Transfer ended before all files arrived")
                        val expected = completion(pending.size, totalBytes, batchHash.digest())
                        if (!Crypto.constantTimeEquals(body, expected)) throw IntegrityException("Invalid batch completion")
                        // No pending entry is published before authenticated batch completion.
                        pending.forEach { p ->
                            checkCancelled(listener)
                            val location = p.sink.commit()
                            saved += location
                            listener.onFileFinished(p.header.fileIndex, sanitizeName(p.header.name), location)
                        }
                        pending.forEach { it.checkpoint?.discard() }
                        complete = true
                        session.sendControl(Wire.T_RECEIPT, expected)
                        break
                    }
                    if (type != Wire.T_FILE_HEADER || pending.size >= TransferLimits.MAX_FILES)
                        throw ProtocolException("Expected bounded file header")
                    val header = FileHeader.decode(body)
                    if (header.fileIndex != pending.size || (declaredCount != null && header.totalFiles != declaredCount))
                        throw ProtocolException("Inconsistent file sequence or count")
                    if (!identities.add(header.transferId.toList())) throw ProtocolException("Replayed transfer identity")
                    declaredCount = header.totalFiles
                    if (totalBytes + header.size > TransferLimits.MAX_BATCH_BYTES) throw ProtocolException("Batch size limit exceeded")
                    val safeName = sanitizeName(header.name)
                    val keys: FileKeys
                    if (header.profile.requiresPassword) {
                        var accepted: FileKeys? = null
                        for (attempt in 1..MAX_PASSWORD_ATTEMPTS) {
                            checkCancelled(listener)
                            val pw = cachedPassword ?: passwords.request(safeName, attempt) ?: break
                            val pwKey = Crypto.pbkdf2(pw, header.passwordSalt, header.pbkdf2Iterations)
                            val candidate = try { FileKeys(session, header, pwKey) } finally { Crypto.wipe(pwKey) }
                            if (Crypto.constantTimeEquals(candidate.passwordCheck, header.passwordCheck)) {
                                accepted = candidate; cachedPassword = pw; break
                            }
                            candidate.close(); pw.fill('\u0000'); cachedPassword = null
                            listener.onLog("Password rejected (attempt $attempt of $MAX_PASSWORD_ATTEMPTS)")
                        }
                        if (accepted == null) {
                            session.sendControl(Wire.T_ACK, byteArrayOf(Wire.ACK_REJECT_PASSWORD.toByte()))
                            throw ProtocolException("Shared password rejected")
                        }
                        keys = accepted
                    } else keys = FileKeys(session, header, null)
                    keys.use { fileKeys ->
                        batchHash.update(body)
                        listener.onFileStarted(header.fileIndex, header.totalFiles, safeName, header.profile, header.size)
                        val digest = MessageDigest.getInstance("SHA-256")
                        val prefix = MessageDigest.getInstance("SHA-256")
                        currentCheckpoint = resumeStore?.open(ResumeDescriptor(header.transferId, header.name,
                            header.mimeType, header.size, header.profile, header.contentHash))
                        val checkpoint = currentCheckpoint
                        var done = 0L
                        checkpoint?.replay { pt ->
                            checkCancelled(listener); digest.update(pt); prefix.update(pt); done += pt.size
                        }
                        val offset = checkpoint?.verifiedChunks ?: 0L
                        if (offset !in 0..header.chunkCount) throw IntegrityException("Invalid saved state")
                        // Create pending storage only after user authentication, password and journal validation.
                        currentSink = sinks.create(safeName, header.mimeType, header.size)
                        val sink = currentSink!!
                        session.sendControl(Wire.T_ACK, byteArrayOf(Wire.ACK_OK.toByte()))
                        session.sendControl(Wire.T_RESUME, ByteArrayOutputStream().also { buffer ->
                            DataOutputStream(buffer).use { it.writeLong(offset); it.write(prefix.digest()) }
                        }.toByteArray())
                        listener.onProgress(header.fileIndex, done, header.size)
                        for (chunk in offset until header.chunkCount) {
                            checkCancelled(listener)
                            val (chunkType, ciphertext) = session.readFrame()
                            if (chunkType != Wire.T_CHUNK) throw ProtocolException("Expected chunk $chunk")
                            val want = minOf(header.chunkSize.toLong(), header.size - done).toInt()
                            if (ciphertext.size != want + Crypto.TAG_BYTES) throw IntegrityException("Invalid encrypted chunk length")
                            val key = fileKeys.keyFor(chunk)
                            val pt = try { Crypto.gcmDecrypt(key, Crypto.nonce(header.fileIndex, chunk),
                                chunkAad(header.fileId, chunk, chunk == header.chunkCount - 1), ciphertext) }
                                finally { if (header.profile.rotation == KeyRotation.PER_CHUNK) Crypto.wipe(key) }
                            try {
                                digest.update(pt)
                                if (checkpoint != null) checkpoint.append(chunk, pt) else sink.output.write(pt)
                                done += pt.size
                            } finally { Crypto.wipe(pt) }
                            listener.onProgress(header.fileIndex, done, header.size)
                        }
                        val claimed = session.expectControl(Wire.T_FILE_TRAILER)
                        val actual = digest.digest()
                        if (done != header.size || !Crypto.constantTimeEquals(claimed, actual) ||
                            !Crypto.constantTimeEquals(header.contentHash, actual)) throw IntegrityException("Whole-file SHA-256 verification failed")
                        checkpoint?.replay { pt -> checkCancelled(listener); sink.output.write(pt) }
                        sink.finishWriting()
                        pending += Pending(header, sink, checkpoint)
                        currentCheckpoint = null; currentSink = null
                        totalBytes += header.size; batchHash.update(actual)
                        session.sendControl(Wire.T_FILE_VERIFIED, actual)
                    }
                }
            }
        } catch (e: Exception) {
            preserve = !listener.isCancelled() && (e is IOException || (e is ProtocolException && e.cause is IOException))
            throw e
        } finally {
            cachedPassword?.fill('\u0000')
            if (!complete) {
                currentSink?.let { runCatching { it.abort() } }
                pending.forEach { runCatching { it.sink.abort() } }
                if (!preserve) {
                    currentCheckpoint?.discard()
                    pending.forEach { it.checkpoint?.discard() }
                }
            }
        }
        return TransferResult(saved, totalBytes, (System.nanoTime() - start) / 1_000_000)
    }

    private fun completion(count: Int, bytes: Long, hash: ByteArray): ByteArray =
        java.nio.ByteBuffer.allocate(44).putInt(count).putLong(bytes).put(hash).array()

    private fun hashSource(file: OutgoingFile, listener: TransferListener): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(256 * 1024)
        var count = 0L
        try {
            file.open().use { stream ->
                while (true) {
                    checkCancelled(listener)
                    val n = stream.read(buffer)
                    if (n < 0) break
                    if (n == 0) throw IOException("Source did not make progress")
                    count += n
                    if (count > file.size) throw IntegrityException("Source is longer than declared size")
                    digest.update(buffer, 0, n)
                }
            }
            if (count != file.size) throw IntegrityException("Source is shorter than declared size")
            return digest.digest()
        } finally { Crypto.wipe(buffer) }
    }

    fun sanitizeName(raw: String): String = raw.substringAfterLast('/').substringAfterLast('\\')
        .filter { !it.isISOControl() && it !in "<>:\"|?*" && Character.getType(it) != Character.FORMAT.toInt() }
        .trim().trimStart('.').take(120).ifEmpty { "received_file" }

    private fun readExact(source: InputStream, buffer: ByteArray, length: Int) {
        var read = 0
        while (read < length) {
            val n = source.read(buffer, read, length - read)
            if (n <= 0) throw IOException("Source ended or stopped making progress")
            read += n
        }
    }
}
