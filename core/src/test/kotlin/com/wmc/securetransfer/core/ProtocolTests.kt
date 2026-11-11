package com.wmc.securetransfer.core

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.*
import java.net.*
import java.nio.ByteBuffer
import java.nio.file.Path
import java.util.concurrent.*
import kotlin.random.Random

class ProtocolTests {
    @TempDir lateinit var temporary: Path
    private class Sink : IncomingSink {
        val bytes = ByteArrayOutputStream()
        var committed = false
        var aborted = false
        override val output get() = bytes
        override fun commit(): String { committed = true; return "test-download" }
        override fun abort() { aborted = true; bytes.reset() }
    }
    private val accept = object : TransferListener { override fun confirmVerification(code: String) = true }
    private data class Outcome(val sender: Throwable?, val receiver: Throwable?, val sinks: List<Sink>, val logs: List<String>)
    private fun exchange(
        files: List<OutgoingFile>, store: ResumeStore? = null,
        sendListener: TransferListener = accept, receiveListener: TransferListener = accept,
        receiverPassword: String = "shared password", senderPassword: String = "shared password",
    ): Outcome {
        val pool = Executors.newFixedThreadPool(2)
        val server = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
        val sinks = java.util.Collections.synchronizedList(mutableListOf<Sink>())
        val logs = java.util.Collections.synchronizedList(mutableListOf<String>())
        fun error(task: () -> Unit): Throwable? = try { task(); null } catch (e: Throwable) { e }
        val receiver = pool.submit(Callable {
            server.accept().use { socket ->
                socket.soTimeout = 4000
                val (input, output) = TransferEngine.streams(socket)
                error { TransferEngine.receive(input, output,
                    { _, _, _ -> Sink().also { sinks += it } },
                    { _, attempt -> if (attempt <= 3) receiverPassword.toCharArray() else null }, receiveListener, store) }
            }
        })
        val sender = pool.submit(Callable {
            Socket(InetAddress.getLoopbackAddress(), server.localPort).use { socket ->
                socket.soTimeout = 4000
                val (input, output) = TransferEngine.streams(socket)
                error { TransferEngine.send(input, output, files, senderPassword.toCharArray(), object : TransferListener by sendListener {
                    override fun onLog(message: String) { logs += message; sendListener.onLog(message) }
                }) }
            }
        })
        try { return Outcome(sender.get(20, TimeUnit.SECONDS), receiver.get(20, TimeUnit.SECONDS), sinks.toList(), logs.toList()) }
        finally { server.close(); pool.shutdownNow() }
    }
    private fun file(data: ByteArray = Random(1).nextBytes(1_200_007), profile: SecurityProfile = SecurityProfile.ENHANCED) =
        OutgoingFile("example.bin", "application/octet-stream", data.size.toLong(), profile) { data.inputStream() }
    private fun header(data: ByteArray, index: Int = 0, count: Int = 1) = FileHeader(index, count, Crypto.random(16),
        "example.bin", "application/octet-stream", data.size.toLong(), SecurityProfile.ENHANCED,
        SecurityProfile.ENHANCED.chunkSize, ByteArray(0), 0, ByteArray(0), Crypto.random(16), Crypto.sha256(data))
    private data class ScriptResult(val error: Throwable?, val sinks: List<Sink>)
    private fun script(block: (SecureSession) -> Unit): ScriptResult {
        val pool = Executors.newSingleThreadExecutor()
        val server = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
        val sinks = mutableListOf<Sink>()
        val receiver = pool.submit(Callable {
            server.accept().use { socket ->
                socket.soTimeout = 4000
                val (input, output) = TransferEngine.streams(socket)
                runCatching { TransferEngine.receive(input, output, { _, _, _ -> Sink().also { sinks += it } },
                    { _, _ -> null }, accept) }.exceptionOrNull()
            }
        })
        try {
            Socket(InetAddress.getLoopbackAddress(), server.localPort).use { socket ->
                socket.soTimeout = 4000
                val (input, output) = TransferEngine.streams(socket)
                SecureSession.handshake(input, output, true).use { session ->
                    session.confirm(accept)
                    runCatching { block(session) }
                }
            }
            return ScriptResult(receiver.get(10, TimeUnit.SECONDS), sinks.toList())
        } finally { server.close(); pool.shutdownNow() }
    }
    private fun start(session: SecureSession, header: FileHeader) {
        session.sendControl(Wire.T_FILE_HEADER, header.encode())
        session.expectAck(); session.expectControl(Wire.T_RESUME)
    }
    private fun chunk(session: SecureSession, header: FileHeader, data: ByteArray, index: Long, last: Boolean) {
        FileKeys(session, header, null).use { keys ->
            session.sendChunk(Crypto.gcmEncrypt(keys.keyFor(index), Crypto.nonce(header.fileIndex, index),
                chunkAad(header.fileId, index, last), data))
            session.flush()
        }
    }

    @Test fun confirmationDefaultsToRejection() {
        val result = exchange(listOf(file(ByteArray(10))), sendListener = object : TransferListener {})
        assertNotNull(result.sender); assertNotNull(result.receiver); assertTrue(result.sinks.isEmpty())
    }
    @Test fun receiverRejectsCodeBeforeCreatingSink() {
        val result = exchange(listOf(file()), receiveListener = object : TransferListener {})
        assertNotNull(result.sender); assertNotNull(result.receiver); assertTrue(result.sinks.isEmpty())
    }
    @Test fun confirmationOnBothSidesEnablesTransfer() {
        val data = Random(9).nextBytes(1_700_000)
        val result = exchange(listOf(file(data)))
        assertNull(result.sender); assertNull(result.receiver)
        assertArrayEquals(data, result.sinks.single().bytes.toByteArray()); assertTrue(result.sinks.single().committed)
    }
    @Test fun wrongPasswordUsesAtMostThreeAttemptsAndCreatesNoDownload() {
        var attempts = 0
        val result = exchange(listOf(file(ByteArray(50), SecurityProfile.MAXIMUM)),
            receiverPassword = "wrong password", receiveListener = object : TransferListener by accept {
                override fun onLog(message: String) { if (message.startsWith("Password rejected")) attempts++ }
            })
        assertEquals(3, attempts); assertTrue(result.sinks.isEmpty()); assertNotNull(result.sender)
    }
    @Test fun sensitiveFileCannotUseWeakerProfileInSender() {
        val sensitive = OutgoingFile("passport.pdf", "application/pdf", 0, SecurityProfile.STANDARD) { byteArrayOf().inputStream() }
        assertThrows(IllegalArgumentException::class.java) {
            TransferEngine.send(DataInputStream(byteArrayOf().inputStream()), DataOutputStream(ByteArrayOutputStream()), listOf(sensitive), null, accept)
        }
    }
    @Test fun sensitiveMetadataCannotUseWeakerProfileInReceiver() {
        val header = header(ByteArray(0)).copy(name = "medical.pdf")
        assertThrows(ProtocolException::class.java) { FileHeader.decode(header.encode()) }
    }
    @Test fun metadataValidationRejectsCountsSizesAndKdfResourceAttacks() {
        val h = header(ByteArray(0))
        listOf(h.copy(totalFiles = 0), h.copy(totalFiles = 1001), h.copy(fileIndex = -1), h.copy(fileIndex = 1),
            h.copy(size = -1), h.copy(size = Long.MAX_VALUE), h.copy(fileId = ByteArray(1)),
            h.copy(chunkSize = Int.MAX_VALUE), h.copy(transferId = ByteArray(0)), h.copy(contentHash = ByteArray(31)),
            h.copy(name = "x".repeat(241)), h.copy(mimeType = "bad\nvalue"),
            h.copy(profile = SecurityProfile.MAXIMUM, chunkSize = SecurityProfile.MAXIMUM.chunkSize,
                passwordSalt = ByteArray(16), passwordCheck = ByteArray(16), pbkdf2Iterations = Int.MAX_VALUE)
        ).forEach { bad -> assertThrows(ProtocolException::class.java) { FileHeader.decode(bad.encode()) } }
        assertThrows(ProtocolException::class.java) { FileHeader.decode(h.encode() + byteArrayOf(0)) }
    }
    @Test fun oversizedFramesRejectedBeforeAllocation() {
        val bytes = ByteBuffer.allocate(4).putInt(Int.MAX_VALUE).array()
        assertThrows(ProtocolException::class.java) { Wire.readBlob(DataInputStream(bytes.inputStream()), Wire.MAX_FRAME) }
        assertThrows(ProtocolException::class.java) { Wire.readBlob(DataInputStream(ByteBuffer.allocate(4).putInt(-1).array().inputStream()), 16) }
    }
    @Test fun endWithoutFilesIsRejected() {
        val result = script { it.sendControl(Wire.T_END, ByteArray(44)) }
        assertTrue(result.error is ProtocolException); assertTrue(result.sinks.isEmpty())
    }
    @Test fun truncatedChunkStreamAbortsPendingDownload() {
        val result = script { session -> start(session, header(ByteArray(600_000))) }
        assertNotNull(result.error); assertTrue(result.sinks.single().aborted); assertFalse(result.sinks.single().committed)
    }
    @Test fun missingChunkCannotBeReplacedByTrailer() {
        val data = ByteArray(600_000)
        val result = script { session ->
            val h = header(data); start(session, h)
            session.sendControl(Wire.T_FILE_TRAILER, Crypto.sha256(data))
        }
        assertTrue(result.error is ProtocolException); assertTrue(result.sinks.single().aborted)
    }
    @Test fun reorderedChunksFailAuthentication() {
        val data = Random(7).nextBytes(600_000)
        val result = script { session ->
            val h = header(data); start(session, h)
            chunk(session, h, data.copyOfRange(h.chunkSize, data.size), 1, true)
        }
        assertTrue(result.error is IntegrityException); assertTrue(result.sinks.single().aborted)
    }
    @Test fun replayedChunkFailsAuthentication() {
        val data = Random(8).nextBytes(2 * SecurityProfile.ENHANCED.chunkSize)
        val result = script { session ->
            val h = header(data); start(session, h)
            val first = data.copyOfRange(0, h.chunkSize)
            chunk(session, h, first, 0, false); chunk(session, h, first, 0, false)
        }
        assertTrue(result.error is IntegrityException); assertTrue(result.sinks.single().aborted)
    }
    @Test fun wrongWholeFileHashPreventsPublication() {
        val data = Random(3).nextBytes(100)
        val result = script { session ->
            val h = header(data); start(session, h); chunk(session, h, data, 0, true)
            session.sendControl(Wire.T_FILE_TRAILER, ByteArray(32))
        }
        assertTrue(result.error is IntegrityException); assertTrue(result.sinks.single().aborted)
    }
    @Test fun authenticatedEarlyEndDoesNotPublishVerifiedFirstFile() {
        val data = ByteArray(10)
        val result = script { session ->
            val h = header(data, count = 2); start(session, h); chunk(session, h, data, 0, true)
            session.sendControl(Wire.T_FILE_TRAILER, Crypto.sha256(data)); session.expectControl(Wire.T_FILE_VERIFIED)
            session.sendControl(Wire.T_END, ByteArray(44))
        }
        assertTrue(result.error is ProtocolException); assertTrue(result.sinks.single().aborted); assertFalse(result.sinks.single().committed)
    }
    @Test fun inconsistentBatchCountsRejected() {
        val data = ByteArray(0)
        val result = script { session ->
            val h = header(data, count = 2); start(session, h); chunk(session, h, data, 0, true)
            session.sendControl(Wire.T_FILE_TRAILER, Crypto.sha256(data)); session.expectControl(Wire.T_FILE_VERIFIED)
            session.sendControl(Wire.T_FILE_HEADER, header(data, index = 1, count = 3).encode())
        }
        assertTrue(result.error is ProtocolException); assertTrue(result.sinks.all { it.aborted && !it.committed })
    }
    @Test fun interruptionResumesVerifiedChunksWithFreshSessionsForEveryProfile() {
        for (profile in SecurityProfile.entries) {
            val root = temporary.resolve(profile.name).toFile()
            val secret = Crypto.random(32)
            val data = Random(99).nextBytes(profile.chunkSize * 2 + 117)
            val source = file(data, profile)
            EncryptedResumeStore(root, secret).use { store ->
                val first = exchange(listOf(source), store, receiveListener = object : TransferListener by accept {
                    override fun onProgress(index: Int, bytesDone: Long, size: Long) {
                        if (bytesDone >= profile.chunkSize) throw IOException("Injected network interruption")
                    }
                })
                assertNotNull(first.receiver); assertTrue(first.sinks.all { it.aborted && !it.committed })
                assertTrue(root.walkTopDown().any { it.name == "0.chunk" })
            }
            // A new store instance validates durable records; new ECDH handshake and password salt are used.
            EncryptedResumeStore(root, secret).use { store ->
                val retried = exchange(listOf(source), store)
                assertNull(retried.sender, "${profile.name}: ${retried.sender}")
                assertNull(retried.receiver, "${profile.name}: ${retried.receiver}")
                assertTrue(retried.logs.any { it.startsWith("Resuming") })
                assertArrayEquals(data, retried.sinks.single().bytes.toByteArray())
                assertTrue(retried.sinks.single().committed)
                assertTrue(root.listFiles().isNullOrEmpty())
            }
        }
    }
    @Test fun explicitCancellationDiscardsJournal() {
        val root = temporary.resolve("cancel").toFile()
        EncryptedResumeStore(root, Crypto.random(32)).use { store ->
            var cancel = false
            val result = exchange(listOf(file()), store, receiveListener = object : TransferListener by accept {
                override fun isCancelled() = cancel
                override fun onProgress(index: Int, bytesDone: Long, size: Long) { if (bytesDone > 0) cancel = true }
            })
            assertNotNull(result.receiver); assertTrue(result.sinks.all { it.aborted })
            assertTrue(root.listFiles().isNullOrEmpty())
        }
    }
    @Test fun savedStateCorruptionFailsClosed() {
        val root = temporary.resolve("corruption").toFile()
        val data = Random(2).nextBytes(10)
        val descriptor = ResumeDescriptor(Crypto.random(16), "file.bin", "application/octet-stream", 10,
            SecurityProfile.ENHANCED, Crypto.sha256(data))
        EncryptedResumeStore(root, Crypto.random(32)).use { store ->
            store.open(descriptor).append(0, data)
            val chunk = root.walkTopDown().first { it.name == "0.chunk" }
            val bytes = chunk.readBytes(); bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte(); chunk.writeBytes(bytes)
            assertThrows(IntegrityException::class.java) { store.open(descriptor) }
            assertTrue(root.listFiles().isNullOrEmpty())
        }
    }
    @Test fun resumeIdentityBindsContentAndProfile() {
        val root = temporary.resolve("identity").toFile()
        val d = ResumeDescriptor(Crypto.random(16), "file.bin", "application/octet-stream", 0,
            SecurityProfile.ENHANCED, Crypto.sha256(ByteArray(0)))
        EncryptedResumeStore(root, Crypto.random(32)).use { store ->
            store.open(d).append(0, ByteArray(0))
            assertThrows(IntegrityException::class.java) { store.open(d.copy(profile = SecurityProfile.STANDARD)) }
        }
    }
    @Test fun expiredJournalIsRemoved() {
        val root = temporary.resolve("expiry").toFile()
        EncryptedResumeStore(root, Crypto.random(32), expiryMillis = 1000).use { store ->
            store.open(ResumeDescriptor(Crypto.random(16), "x", "application/octet-stream", 0,
                SecurityProfile.STANDARD, Crypto.sha256(ByteArray(0))))
            store.cleanup(System.currentTimeMillis() + 2000)
            assertTrue(root.listFiles().isNullOrEmpty())
        }
    }
    @Test fun quotaPreventsResourceExhaustion() {
        val root = temporary.resolve("quota").toFile()
        EncryptedResumeStore(root, Crypto.random(32), maxBytes = 100).use { store ->
            val checkpoint = store.open(ResumeDescriptor(Crypto.random(16), "x", "x", 200,
                SecurityProfile.STANDARD, Crypto.sha256(ByteArray(200))))
            assertThrows(ProtocolException::class.java) { checkpoint.append(0, ByteArray(200)) }
        }
    }
    @Test fun overrideAndThermalRulesNeverWeakenMandatorySensitiveProtection() {
        val trusted = DeviceContext(NetworkRisk.TRUSTED, 80, false, false)
        val publicHot = trusted.copy(networkRisk = NetworkRisk.UNTRUSTED, thermalStressed = true)
        val ordinary = FileFacts("photo.jpg", "image/jpeg", 50)
        val sensitive = FileFacts("passport.pdf", "application/pdf", 50)
        assertEquals(SecurityProfile.ENHANCED, ContextAnalyzer.assess(ordinary, publicHot).profile)
        assertEquals(SecurityProfile.MAXIMUM, ContextAnalyzer.assess(sensitive, publicHot).profile)
        assertEquals(SecurityProfile.MAXIMUM, ContextAnalyzer.assess(sensitive, trusted).withOverride(SecurityProfile.STANDARD))
        assertEquals(SecurityProfile.ENHANCED, ContextAnalyzer.assess(ordinary, trusted).withOverride(SecurityProfile.STANDARD))
        assertEquals(SecurityProfile.MAXIMUM, ContextAnalyzer.assess(ordinary, trusted).withOverride(SecurityProfile.MAXIMUM))
        assertEquals(SecurityProfile.MAXIMUM, ContextAnalyzer.assess(ordinary, trusted.copy(networkRisk = NetworkRisk.UNTRUSTED, batteryPercent = 10, isCharging = true)).profile)
    }
    @Test fun namesRemoveTraversalControlsAndBidirectionalSpoofing() {
        assertEquals("evil.txt", TransferEngine.sanitizeName("../../evil\u0000\u202E.txt"))
        assertTrue(TransferEngine.sanitizeName("x".repeat(1000)).length <= 120)
    }
    @Test fun chunkKeysAndNoncesAreSeparated() {
        val pairs = (0..4).flatMap { file -> (0L..4L).map { chunk -> Crypto.nonce(file, chunk).toList() } }
        assertEquals(pairs.size, pairs.distinct().size)
        val key = Crypto.random(32)
        assertFalse(Crypto.hkdf(key, null, "SAT/chunk/0").contentEquals(Crypto.hkdf(key, null, "SAT/chunk/1")))
    }
    @Test fun invalidBatchCompletionHashPreventsPublication() {
        val data = ByteArray(10)
        val result = script { session ->
            val h = header(data); start(session, h); chunk(session, h, data, 0, true)
            session.sendControl(Wire.T_FILE_TRAILER, Crypto.sha256(data)); session.expectControl(Wire.T_FILE_VERIFIED)
            session.sendControl(Wire.T_END, ByteBuffer.allocate(44).putInt(1).putLong(10).put(ByteArray(32)).array())
        }
        assertTrue(result.error is IntegrityException)
        assertTrue(result.sinks.single().aborted); assertFalse(result.sinks.single().committed)
    }
    @Test fun repeatedTransferIdentityIsRejectedAcrossFiles() {
        val data = ByteArray(0)
        val result = script { session ->
            val h = header(data, count = 2); start(session, h); chunk(session, h, data, 0, true)
            session.sendControl(Wire.T_FILE_TRAILER, Crypto.sha256(data)); session.expectControl(Wire.T_FILE_VERIFIED)
            session.sendControl(Wire.T_FILE_HEADER, h.copy(fileIndex = 1).encode())
        }
        assertTrue(result.error is ProtocolException); assertTrue(result.sinks.all { it.aborted && !it.committed })
    }
    @Test fun p256OnlyRejectsOtherEllipticCurves() {
        val other = java.security.KeyPairGenerator.getInstance("EC").apply {
            initialize(java.security.spec.ECGenParameterSpec("secp384r1"))
        }.generateKeyPair()
        assertThrows(ProtocolException::class.java) { KeyExchange.decodePublic(other.public.encoded) }
        assertThrows(ProtocolException::class.java) { KeyExchange.decodePublic(byteArrayOf(1, 2, 3)) }
    }
    @Test fun handshakeCommitmentRejectsChangedReveal() {
        val key = KeyExchange.generate().public.encoded
        val nonce = Crypto.random(32)
        val malicious = ByteArrayOutputStream().also { bytes ->
            DataOutputStream(bytes).use { out ->
                out.write(Wire.MAGIC); out.writeByte(Wire.VERSION)
                Wire.writeBlob(out, Crypto.sha256(Wire.MAGIC, byteArrayOf(Wire.VERSION.toByte()), key, nonce))
                Wire.writeBlob(out, key); out.write(nonce.map { (it.toInt() xor 1).toByte() }.toByteArray())
            }
        }.toByteArray()
        assertThrows(IntegrityException::class.java) {
            SecureSession.handshake(DataInputStream(malicious.inputStream()), DataOutputStream(ByteArrayOutputStream()), false)
        }
    }
    @Test fun zeroByteFilesAlsoUseAuthenticatedRecoveryAndCompletion() {
        val root = temporary.resolve("empty").toFile()
        EncryptedResumeStore(root, Crypto.random(32)).use { store ->
            val result = exchange(listOf(file(ByteArray(0))), store)
            assertNull(result.sender); assertNull(result.receiver)
            assertTrue(result.sinks.single().committed); assertEquals(0, result.sinks.single().bytes.size())
            assertTrue(root.listFiles().isNullOrEmpty())
        }
    }
    @Test fun oversizedSourceAndSourceMutationAreRejected() {
        val tooLong = OutgoingFile("x", "x", 1, SecurityProfile.STANDARD) { ByteArray(2).inputStream() }
        assertNotNull(exchange(listOf(tooLong)).sender)
        var opened = 0
        val changing = OutgoingFile("x", "x", 10, SecurityProfile.STANDARD) {
            val value = if (opened++ == 0) 1.toByte() else 2.toByte()
            ByteArray(10) { value }.inputStream()
        }
        val result = exchange(listOf(changing))
        assertNotNull(result.sender); assertTrue(result.sinks.all { it.aborted && !it.committed })
    }
}
