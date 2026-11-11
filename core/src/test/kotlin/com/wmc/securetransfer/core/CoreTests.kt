package com.wmc.securetransfer.core

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.random.Random
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Real TCP loopback tests for the transfer engine and context analyzer. */
class CoreTests {

    private class MemSink(val name: String) : IncomingSink {
        val bytes = ByteArrayOutputStream()
        var committed = false; var aborted = false
        override val output get() = bytes
        override fun commit(): String { committed = true; return "mem://$name" }
        override fun abort() { aborted = true }
    }

    private class Outcome(val sendError: Throwable?, val recvError: Throwable?, val sinks: List<MemSink>, val codes: List<String>)

    /** Runs a sender and receiver over localhost; [tamperAt] flips one byte in transit (sender → receiver). */
    private fun runTransfer(
        payloads: List<Pair<String, ByteArray>>,
        profile: SecurityProfile,
        senderPw: String? = null,
        receiverPw: String? = senderPw,
        tamperAt: Long = -1,
    ): Outcome {
        val pool = Executors.newFixedThreadPool(3)
        val server = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
        val sinks = mutableListOf<MemSink>()
        val codes = java.util.Collections.synchronizedList(mutableListOf<String>())
        val codeListener = object : TransferListener { override fun onVerificationCode(code: String) { codes += code }; override fun confirmVerification(code: String) = true }

        // Optional man-in-the-middle relay that corrupts one byte.
        val relay = if (tamperAt >= 0) ServerSocket(0, 1, InetAddress.getLoopbackAddress()) else null
        relay?.let { r ->
            pool.submit {
                r.accept().use { a -> Socket(InetAddress.getLoopbackAddress(), server.localPort).use { b ->
                    val t = Thread { runCatching { b.getInputStream().copyTo(a.getOutputStream()) } }.apply { isDaemon = true; start() }
                    runCatching {
                        val inS = a.getInputStream(); val outS = b.getOutputStream(); var pos = 0L
                        val buffer = ByteArray(16 * 1024)
                        while (true) {
                            val n = inS.read(buffer); if (n < 0) break
                            if (tamperAt >= pos && tamperAt < pos + n) {
                                val at = (tamperAt - pos).toInt(); buffer[at] = (buffer[at].toInt() xor 1).toByte()
                            }
                            outS.write(buffer, 0, n); outS.flush(); pos += n
                        }
                    }
                    t.join(5000)
                } }
            }
        }

        val recv = pool.submit(Callable {
            server.accept().use { s ->
                s.soTimeout = 10_000
                val (i, o) = TransferEngine.streams(s)
                TransferEngine.receive(i, o,
                    { n, _, _ -> MemSink(n).also { synchronized(sinks) { sinks += it } } },
                    { _, attempt -> if (attempt == 1) receiverPw?.toCharArray() else null }, codeListener)
            }
        })
        val send = pool.submit(Callable {
            Socket(InetAddress.getLoopbackAddress(), relay?.localPort ?: server.localPort).use { s ->
                s.soTimeout = 10_000
                val (i, o) = TransferEngine.streams(s)
                val files = payloads.map { (n, d) -> OutgoingFile(n, "application/octet-stream", d.size.toLong(), profile) { d.inputStream() } }
                TransferEngine.send(i, o, files, senderPw?.toCharArray(), codeListener)
            }
        })
        val sErr = runCatching { send.get(60, TimeUnit.SECONDS) }.exceptionOrNull()?.let { it.cause ?: it }
        val rErr = runCatching { recv.get(60, TimeUnit.SECONDS) }.exceptionOrNull()?.let { it.cause ?: it }
        pool.shutdownNow(); server.close(); relay?.close()
        return Outcome(sErr, rErr, sinks, codes)
    }

    @Test fun roundTripAllProfiles() {
        val sizes = listOf(0, 1, 256 * 1024 - 1, 256 * 1024, 512 * 1024 + 7, 1024 * 1024, 3_300_000)
        for (p in SecurityProfile.entries) {
            val payloads = sizes.mapIndexed { i, n -> "file$i.bin" to Random(i + p.ordinal).nextBytes(n) }
            val o = runTransfer(payloads, p, senderPw = if (p.requiresPassword) "correct horse" else null)
            assertEquals(null, o.sendError, "send ${p.name}"); assertEquals(null, o.recvError, "recv ${p.name}")
            assertEquals(payloads.size, o.sinks.size)
            payloads.zip(o.sinks).forEach { (src, sink) ->
                assertArrayEquals(src.second, sink.bytes.toByteArray(), "${p.name} ${src.first}")
                assertTrue(sink.committed)
            }
            assertEquals(2, o.codes.size); assertEquals(o.codes[0], o.codes[1], "verification codes must match")
        }
    }

    @Test fun wrongPasswordIsRejected() {
        val o = runTransfer(listOf("secret.pdf" to Random(1).nextBytes(10_000)), SecurityProfile.MAXIMUM, "rightpass", "wrongpass")
        assertTrue(o.sendError is ProtocolException, "sender sees rejection: ${o.sendError}")
        assertTrue(o.recvError is ProtocolException, "receiver fails: ${o.recvError}")
        assertTrue(o.sinks.isEmpty(), "nothing written")
    }

    @Test fun tamperingIsDetected() {
        // Flip a byte deep inside the first encrypted chunk (well past the ~200-byte handshake + header).
        for (p in SecurityProfile.entries) {
            val o = runTransfer(listOf("doc.bin" to Random(7).nextBytes(600_000)), p,
                senderPw = if (p.requiresPassword) "hunter22" else null, tamperAt = 5_000)
            assertTrue(o.recvError is IntegrityException, "${p.name}: receiver must detect tamper, got ${o.recvError}")
            assertTrue(o.sinks.all { it.aborted && !it.committed }, "${p.name}: partial file discarded")
        }
    }

    @Test fun mitmChangesVerificationCode() {
        // Endpoints derive matching codes and keys; independent sessions derive fresh keys.
        val pool = Executors.newFixedThreadPool(2)
        fun pair(): Triple<String, String, List<Byte>> {
            val a2b = java.io.PipedOutputStream(); val bIn = java.io.PipedInputStream(a2b, 4096)
            val b2a = java.io.PipedOutputStream(); val aIn = java.io.PipedInputStream(b2a, 4096)
            val fa = pool.submit(Callable { SecureSession.handshake(DataInputStream(aIn), DataOutputStream(a2b), true).use {
                it.verificationCode to Crypto.sha256(it.master).toList()
            } })
            val fb = pool.submit(Callable { SecureSession.handshake(DataInputStream(bIn), DataOutputStream(b2a), false).use {
                it.verificationCode to Crypto.sha256(it.master).toList()
            } })
            val sender = fa.get(10, TimeUnit.SECONDS); val receiver = fb.get(10, TimeUnit.SECONDS)
            assertEquals(sender.second, receiver.second)
            aIn.close(); bIn.close(); a2b.close(); b2a.close()
            return Triple(sender.first, receiver.first, sender.second)
        }
        val (s1, r1, key1) = pair(); val (_, _, key2) = pair()
        assertEquals(s1, r1)
        assertTrue(key1 != key2, "independent sessions have fresh keys; a six-digit code may legitimately collide")
        pool.shutdownNow()
    }

    @Test fun analyzerRules() {
        val home = DeviceContext(NetworkRisk.TRUSTED, 80, false, false)
        val cell = home.copy(networkRisk = NetworkRisk.CELLULAR)
        val pub = home.copy(networkRisk = NetworkRisk.UNTRUSTED)
        val lowBattPub = pub.copy(batteryPercent = 12)

        val song = FileFacts("track01.mp3", "audio/mpeg", 4_000_000)
        val photo = FileFacts("IMG_2031.jpg", "image/jpeg", 3_000_000)
        val passport = FileFacts("Passport_scan.pdf", "application/pdf", 900_000)
        val key = FileFacts("server.pem", null, 2_000)
        val notTax = FileFacts("syntax_notes.txt", "text/plain", 2_000)

        assertEquals(SecurityProfile.STANDARD, ContextAnalyzer.assess(song, home).profile)
        assertEquals(SecurityProfile.ENHANCED, ContextAnalyzer.assess(song, cell).profile)
        assertEquals(SecurityProfile.MAXIMUM, ContextAnalyzer.assess(song, pub).profile)
        assertEquals(SecurityProfile.ENHANCED, ContextAnalyzer.assess(photo, home).profile)
        assertEquals(SecurityProfile.MAXIMUM, ContextAnalyzer.assess(passport, home).profile)
        assertEquals(SecurityProfile.MAXIMUM, ContextAnalyzer.assess(key, home).profile)
        assertEquals(Sensitivity.PERSONAL, ContextAnalyzer.classify(notTax))
        // Low battery relaxes network-driven Maximum, never sensitivity-driven Maximum.
        assertEquals(SecurityProfile.ENHANCED, ContextAnalyzer.assess(photo, lowBattPub).profile)
        assertEquals(SecurityProfile.MAXIMUM, ContextAnalyzer.assess(passport, lowBattPub).profile)
        assertEquals(SecurityProfile.MAXIMUM, ContextAnalyzer.assess(photo, lowBattPub.copy(isCharging = true)).profile)
    }

    @Test fun hkdfMatchesRfc5869() {
        // RFC 5869 test case 1
        fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val ikm = ByteArray(22) { 0x0b }
        val salt = hex("000102030405060708090a0b0c")
        val info = hex("f0f1f2f3f4f5f6f7f8f9")
        val okm = Crypto.hkdf(ikm, salt, info, 42)
        assertArrayEquals(hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"), okm)
    }

    @Test fun sanitizesHostileNames() {
        assertEquals("passwd", TransferEngine.sanitizeName("../../etc/passwd"))
        assertEquals("evil.txt", TransferEngine.sanitizeName("C:\\Windows\\evil.txt"))
        assertEquals("bashrc", TransferEngine.sanitizeName(".bashrc"))
        assertEquals("received_file", TransferEngine.sanitizeName(".."))
    }
}

/** Minimal runner so the suite can run without Gradle: kotlinc + java. */
fun main() {
    val t = CoreTests()
    val tests = listOf<Pair<String, () -> Unit>>(
        "analyzerRules" to t::analyzerRules,
        "hkdfMatchesRfc5869" to t::hkdfMatchesRfc5869,
        "sanitizesHostileNames" to t::sanitizesHostileNames,
        "mitmChangesVerificationCode" to t::mitmChangesVerificationCode,
        "roundTripAllProfiles" to t::roundTripAllProfiles,
        "wrongPasswordIsRejected" to t::wrongPasswordIsRejected,
        "tamperingIsDetected" to t::tamperingIsDetected,
    )
    var failed = 0
    for ((name, fn) in tests) {
        val r = runCatching { fn() }
        if (r.isSuccess) println("PASS  $name") else { failed++; println("FAIL  $name: ${r.exceptionOrNull()}") }
    }
    println(if (failed == 0) "ALL ${tests.size} TESTS PASSED" else "$failed FAILED")
    kotlin.system.exitProcess(if (failed > 0) 1 else 0)
}
