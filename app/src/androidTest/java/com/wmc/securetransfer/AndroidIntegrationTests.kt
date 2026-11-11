package com.wmc.securetransfer

import android.Manifest
import android.app.NotificationManager
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.content.ContentResolver
import android.provider.MediaStore
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.action.ViewActions.scrollTo
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.*
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.wmc.securetransfer.core.*
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class AndroidIntegrationTests {
    private val app get() = ApplicationProvider.getApplicationContext<TransferApplication>()
    @Before fun permissions() {
        if (Build.VERSION.SDK_INT >= 33) InstrumentationRegistry.getInstrumentation().uiAutomation
            .grantRuntimePermission(app.packageName, Manifest.permission.POST_NOTIFICATIONS)
    }
    @After fun cleanup() {
        app.transfers.cancelAll()
        await { !app.transfers.state.value.busy && !app.transfers.state.value.receiving }
    }
    private fun await(condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 10_000
        while (!condition() && System.currentTimeMillis() < deadline) Thread.sleep(50)
        assertTrue("Condition did not become true within 10 seconds: ${app.transfers.state.value.progressLabel}; ${app.transfers.state.value.log.takeLast(6)}", condition())
    }

    @Test fun homeAndReceiveModeSurviveActivityRecreation() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            onView(withId(R.id.modeReceive)).perform(scrollTo(), click())
            onView(withId(R.id.receiveCard)).check(matches(isDisplayed()))
            scenario.recreate()
            onView(withId(R.id.modeReceive)).check(matches(isChecked()))
            onView(withId(R.id.receiveCard)).check(matches(isDisplayed()))
            assertFalse(app.transfers.state.value.p2pStatus.contains("channel closed"))
        }
    }

    @Test fun foregroundReceiverSurvivesRecreationAndBackgroundAndCancels() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            onView(withId(R.id.modeReceive)).perform(scrollTo(), click())
            onView(withId(R.id.receiveButton)).perform(scrollTo(), click())
            await { app.transfers.state.value.receiving }
            await { app.getSystemService(NotificationManager::class.java).activeNotifications.any { it.id == 8988 } }
            scenario.recreate()
            assertTrue(app.transfers.state.value.receiving)
            scenario.moveToState(Lifecycle.State.CREATED)
            assertTrue(app.transfers.state.value.receiving)
            assertTrue(app.getSystemService(NotificationManager::class.java).activeNotifications.any { it.id == 8988 })
            // Exercise the notification's actual cancellation PendingIntent.
            val notice = app.getSystemService(NotificationManager::class.java).activeNotifications.first { it.id == 8988 }
            notice.notification.actions.first().actionIntent.send()
            await { !app.transfers.state.value.receiving }
            await { app.getSystemService(NotificationManager::class.java).activeNotifications.none { it.id == 8988 } }
        }
    }

    @Test fun mediaStoreKeepsPendingFilesHiddenAndAbortDeletesThem() {
        val resolver = app.contentResolver
        val name = "integration_abort_${System.nanoTime()}.bin"
        val sink = DownloadsSink(resolver, name, "application/octet-stream")
        sink.output.write(byteArrayOf(1, 2, 3))
        fun count(includePending: Boolean): Int {
            val columns = arrayOf(MediaStore.MediaColumns._ID, MediaStore.MediaColumns.IS_PENDING)
            val selection = "${MediaStore.MediaColumns.DISPLAY_NAME} = ?"
            val args = arrayOf(name)
            val collection = MediaStore.Downloads.EXTERNAL_CONTENT_URI
            val cursor = if (Build.VERSION.SDK_INT >= 30) resolver.query(collection, columns, Bundle().apply {
                putString(ContentResolver.QUERY_ARG_SQL_SELECTION, selection)
                putStringArray(ContentResolver.QUERY_ARG_SQL_SELECTION_ARGS, args)
                putInt(MediaStore.QUERY_ARG_MATCH_PENDING, if (includePending) MediaStore.MATCH_INCLUDE else MediaStore.MATCH_EXCLUDE)
            }, null) else {
                @Suppress("DEPRECATION")
                resolver.query(if (includePending) MediaStore.setIncludePending(collection) else collection, columns, selection, args, null)
            }
            return cursor!!.use { rows ->
                if (rows.moveToFirst()) assertEquals(1, rows.getInt(1))
                rows.count
            }
        }
        assertEquals(0, count(false))
        assertEquals(1, count(true))
        sink.abort()
        assertEquals(0, count(true))
    }

    @Test fun loopbackEncryptedBatchIsPublishedWithExactBytesForAllProfiles() {
        val resolver = app.contentResolver
        val pool = Executors.newFixedThreadPool(2)
        val server = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
        val created = mutableListOf<String>()
        val accepted = object : TransferListener { override fun confirmVerification(code: String) = true }
        val data = ByteArray(1_100_007) { (it % 251).toByte() }
        val received = pool.submit(Callable {
            server.accept().use { socket ->
                socket.soTimeout = 30_000
                val (input, output) = TransferEngine.streams(socket)
                TransferEngine.receive(input, output, { name, mime, _ -> DownloadsSink(resolver, name, mime) },
                    { _, _ -> "integration password".toCharArray() }, accepted, AndroidResumeStore.create(app)).files
            }
        })
        try {
            Socket(InetAddress.getLoopbackAddress(), server.localPort).use { socket ->
                socket.soTimeout = 30_000
                val (input, output) = TransferEngine.streams(socket)
                val files = SecurityProfile.entries.map { profile ->
                    val name = "integration_${profile.name}_${System.nanoTime()}.bin"
                    created += name
                    OutgoingFile(name, "application/octet-stream", data.size.toLong(), profile) { data.inputStream() }
                }
                assertEquals(3, TransferEngine.send(input, output, files, "integration password".toCharArray(), accepted).files.size)
            }
            val locations = received.get(60, TimeUnit.SECONDS)
            assertEquals(3, locations.size)
            created.forEach { name ->
                resolver.query(MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                    arrayOf(MediaStore.MediaColumns._ID, MediaStore.MediaColumns.IS_PENDING),
                    "${MediaStore.MediaColumns.DISPLAY_NAME} = ?", arrayOf(name), null)!!.use { cursor ->
                    assertTrue(cursor.moveToFirst()); assertEquals(0, cursor.getInt(1))
                    val uri = android.content.ContentUris.withAppendedId(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cursor.getLong(0))
                    assertArrayEquals(data, resolver.openInputStream(uri)!!.use { it.readBytes() })
                }
            }
        } finally {
            server.close(); pool.shutdownNow()
            created.forEach { name -> resolver.delete(MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                "${MediaStore.MediaColumns.DISPLAY_NAME} = ?", arrayOf(name)) }
        }
    }

    @Test fun orphanedPendingDownloadsAreRemovedOnStartupCleanup() {
        val resolver = app.contentResolver
        val name = "integration_orphan_${System.nanoTime()}.bin"
        val sink = DownloadsSink(resolver, name, "application/octet-stream")
        sink.output.write(byteArrayOf(5)); sink.finishWriting()
        DownloadsSink.cleanup(resolver, app.packageName)
        try {
            assertThrows(IllegalStateException::class.java) { sink.commit() }
        } finally { sink.abort() }
    }

    @Test fun coordinatorPromptsForCodeAfterRecreationAndReceivesRealFile() {
        val resolver = app.contentResolver
        val name = "integration_ui_${System.nanoTime()}.bin"
        val data = ByteArray(1_100_001) { (it % 251).toByte() }
        val pool = Executors.newSingleThreadExecutor()
        val code = java.util.concurrent.CompletableFuture<String>()
        val confirmed = java.util.concurrent.CompletableFuture<Boolean>()
        try {
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                onView(withId(R.id.modeReceive)).perform(scrollTo(), click())
                onView(withId(R.id.receiveButton)).perform(scrollTo(), click())
                val sender = pool.submit(Callable {
                    val deadline = System.currentTimeMillis() + 10_000
                    var socket: Socket? = null
                    while (socket == null && System.currentTimeMillis() < deadline) {
                        val candidate = Socket()
                        try { candidate.connect(java.net.InetSocketAddress("127.0.0.1", TransferEngine.DEFAULT_PORT), 1000); socket = candidate }
                        catch (_: java.io.IOException) { candidate.close(); Thread.sleep(100) }
                    }
                    checkNotNull(socket).use {
                        it.soTimeout = 30_000
                        val (input, output) = TransferEngine.streams(it)
                        TransferEngine.send(input, output,
                            listOf(OutgoingFile(name, "application/octet-stream", data.size.toLong(), SecurityProfile.ENHANCED) { data.inputStream() }),
                            null, object : TransferListener {
                                override fun confirmVerification(value: String): Boolean {
                                    code.complete(value)
                                    return confirmed.get(30, TimeUnit.SECONDS)
                                }
                            })
                    }
                })
                await { app.transfers.verificationRequest.value != null }
                assertEquals(code.get(10, TimeUnit.SECONDS), app.transfers.verificationRequest.value!!.code)
                assertEquals(0, app.transfers.state.value.progress)
                scenario.recreate()
                onView(withText("Codes match")).check(matches(isDisplayed())).perform(click())
                confirmed.complete(true)
                assertEquals(1, sender.get(40, TimeUnit.SECONDS).files.size)
                await { !app.transfers.state.value.receiving }
                assertFalse(app.transfers.state.value.failed)
                resolver.query(MediaStore.Downloads.EXTERNAL_CONTENT_URI, arrayOf(MediaStore.MediaColumns._ID),
                    "${MediaStore.MediaColumns.DISPLAY_NAME} = ?", arrayOf(name), null)!!.use { rows ->
                    assertTrue(rows.moveToFirst())
                    val uri = android.content.ContentUris.withAppendedId(MediaStore.Downloads.EXTERNAL_CONTENT_URI, rows.getLong(0))
                    assertArrayEquals(data, resolver.openInputStream(uri)!!.use { it.readBytes() })
                }
            }
        } finally {
            confirmed.complete(false); app.transfers.cancelAll(); pool.shutdownNow()
            resolver.delete(MediaStore.Downloads.EXTERNAL_CONTENT_URI, "${MediaStore.MediaColumns.DISPLAY_NAME} = ?", arrayOf(name))
        }
    }

    @Test fun senderUiTransfersSelectedDocumentAndRejectsInvalidAddress() {
        val resolver = app.contentResolver
        val name = "sender_ui_${System.nanoTime()}.bin"
        val data = ByteArray(4_200_003) { (it % 251).toByte() }
        val source = DownloadsSink(resolver, name, "application/octet-stream")
        source.output.write(data)
        val location = source.commit()
        val uri = Uri.parse(location.substringAfterLast('(').removeSuffix(")"))
        val server = ServerSocket(TransferEngine.DEFAULT_PORT, 1, InetAddress.getByName("127.0.0.1"))
        server.soTimeout = 15_000
        val pool = Executors.newSingleThreadExecutor()
        val peerCode = java.util.concurrent.CompletableFuture<String>()
        val bytes = java.io.ByteArrayOutputStream()
        try {
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                scenario.onActivity {
                    app.transfers.setMode(Mode.SEND)
                    app.transfers.clearFiles()
                    app.transfers.addFiles(listOf(uri))
                }
                await { !app.transfers.state.value.preparingFiles }
                assertEquals(1, app.transfers.state.value.files.size)
                scenario.onActivity {
                    assertNotNull(app.transfers.send("invalid-address", "sender password".toCharArray()))
                    assertFalse(app.transfers.state.value.busy)
                }
                val received = pool.submit(Callable {
                    server.accept().use { socket ->
                        socket.soTimeout = 30_000
                        val (input, output) = TransferEngine.streams(socket)
                        TransferEngine.receive(input, output, { _, _, _ -> object : IncomingSink {
                            override val output get() = bytes
                            override fun commit() = "test receiver"
                            override fun abort() { bytes.reset() }
                        } }, { _, _ -> "sender password".toCharArray() }, object : TransferListener {
                            override fun confirmVerification(code: String): Boolean { peerCode.complete(code); return true }
                        })
                    }
                })
                scenario.onActivity { assertNull(app.transfers.send("127.0.0.1", "sender password".toCharArray())) }
                await { app.transfers.verificationRequest.value != null }
                assertEquals(peerCode.get(10, TimeUnit.SECONDS), app.transfers.verificationRequest.value!!.code)
                onView(withText("Codes match")).perform(click())
                assertEquals(1, received.get(40, TimeUnit.SECONDS).files.size)
                await { !app.transfers.state.value.busy }
                assertFalse(app.transfers.state.value.failed)
                assertTrue(app.transfers.state.value.progressLabel.contains("delivered"))
                assertArrayEquals(data, bytes.toByteArray())
            }
        } finally {
            app.transfers.cancelAll(); app.transfers.clearFiles()
            server.close(); pool.shutdownNow(); resolver.delete(uri, null, null)
        }
    }

    @Test fun switchingFileDirectionRetainsNegotiatedGroupOwnerAddress() {
        try {
            app.transfers.setMode(Mode.RECEIVE)
            app.transfers.onP2pConnection(true, false, "192.168.49.1")
            app.transfers.setMode(Mode.SEND)
            assertEquals("192.168.49.1", app.transfers.state.value.p2pHost)
            app.transfers.setMode(Mode.RECEIVE)
            assertNull(app.transfers.state.value.p2pHost)
            app.transfers.onP2pConnection(true, true, "192.168.49.1")
            app.transfers.setMode(Mode.SEND)
            assertNull(app.transfers.state.value.p2pHost)
        } finally { app.transfers.onP2pConnection(false, false, null) }
    }

    @Test fun androidKeystoreResumesEncryptedCheckpointAcrossStoreInstances() {
        val context = app
        val data = byteArrayOf(42, 10, 90)
        val descriptor = ResumeDescriptor(Crypto.random(16), "checkpoint.bin", "application/octet-stream", 3,
            SecurityProfile.ENHANCED, Crypto.sha256(data))
        AndroidResumeStore.create(context).use { store -> store.open(descriptor).append(0, data) }
        AndroidResumeStore.create(context).use { store ->
            val checkpoint = store.open(descriptor)
            assertEquals(1L, checkpoint.verifiedChunks)
            checkpoint.replay { assertArrayEquals(data, it) }
            checkpoint.discard()
        }
    }
}
