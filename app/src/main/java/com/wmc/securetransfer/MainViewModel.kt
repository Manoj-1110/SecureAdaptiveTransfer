package com.wmc.securetransfer

import android.app.Application
import android.content.Intent
import android.net.ConnectivityManager
import android.net.InetAddresses
import android.net.Network
import android.net.NetworkCapabilities
import android.net.Uri
import android.os.SystemClock
import androidx.core.content.ContextCompat
import com.wmc.securetransfer.core.*
import com.wmc.securetransfer.core.ProtocolException
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import java.io.IOException
import java.net.*
import java.time.LocalTime
import java.time.format.DateTimeFormatter
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

enum class Mode { SEND, RECEIVE }

data class UiState(
    val mode: Mode = Mode.SEND,
    val files: List<PickedFile> = emptyList(),
    val assessments: List<Assessment> = emptyList(),
    val network: Telemetry.NetworkReading? = null,
    val device: DeviceContext? = null,
    val override: SecurityProfile? = null,
    val userSaysPublic: Boolean = false,
    val p2pStatus: String = "Choose Wi-Fi Direct or use the receiver's local Wi-Fi IP",
    val p2pHost: String? = null,
    val p2pConnected: Boolean = false,
    val p2pIsOwner: Boolean = false,
    val p2pOwnerAddress: String? = null,
    val busy: Boolean = false,
    val preparingFiles: Boolean = false,
    val receiving: Boolean = false,
    val verificationCode: String? = null,
    val verificationPending: Boolean = false,
    val progressLabel: String = "Choose Send files or Receive files to begin",
    val progress: Int = 0,
    val progressIndeterminate: Boolean = false,
    val failed: Boolean = false,
    val log: List<String> = emptyList(),
    val myAddresses: List<String> = emptyList(),
) {
    fun profileFor(a: Assessment) = a.withOverride(override)
    val needsPassword get() = assessments.any { profileFor(it).requiresPassword }
}
class PasswordRequest(val fileName: String, val attempt: Int, val answer: CompletableDeferred<CharArray?>)
class VerificationRequest(val code: String, val answer: CompletableDeferred<Boolean>)

/** Owns real transfer work independently of Activity lifecycle; TransferService supplies foreground execution. */
class TransferCoordinator(private val app: Application) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val telemetry = Telemetry(app)
    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state
    private val _passwordRequest = MutableStateFlow<PasswordRequest?>(null)
    val passwordRequest: StateFlow<PasswordRequest?> = _passwordRequest
    private val _verificationRequest = MutableStateFlow<VerificationRequest?>(null)
    val verificationRequest: StateFlow<VerificationRequest?> = _verificationRequest
    private val checkpoints by lazy { AndroidResumeStore.create(app, ::log) }
    private val cancelled = AtomicBoolean(false)
    private val storageReady = CompletableDeferred<Unit>()
    @Volatile private var activeSocket: Socket? = null
    @Volatile private var serverSocket: ServerSocket? = null
    private var job: Job? = null
    private val identities = mutableMapOf<Uri, ByteArray>()
    private val connectivity = app.getSystemService(ConnectivityManager::class.java)
    private val netCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = refreshContext()
        override fun onLost(network: Network) = refreshContext()
    }

    init {
        runCatching { connectivity.registerDefaultNetworkCallback(netCallback) }
            .onFailure { log("Network context monitoring unavailable: ${it.message}") }
        runCatching { telemetry.observeLocalWifi(::refreshContext) }
            .onFailure { log("Local Wi-Fi context monitoring unavailable: ${it.message}") }
        scope.launch(Dispatchers.IO) {
            try {
                runCatching { DownloadsSink.cleanup(app.contentResolver, app.packageName) }
                    .onFailure { log("Could not remove old pending downloads: ${it.message}") }
                runCatching { checkpoints.cleanup() }.onFailure { log("Private checkpoint storage unavailable: ${it.message}") }
                telemetry.cleanupStagedFiles()
            } finally { storageReady.complete(Unit) }
        }
        refreshContext()
    }

    fun refreshContext() {
        scope.launch(Dispatchers.Default) {
            _state.update { current ->
                val net = telemetry.network(current.p2pConnected, current.userSaysPublic)
                val dev = telemetry.device(net)
                current.copy(network = net, device = dev,
                    assessments = current.files.map { ContextAnalyzer.assess(it.facts, dev) },
                    myAddresses = telemetry.localIpv4Addresses())
            }
        }
    }
    fun setMode(mode: Mode) {
        _state.update { current ->
            if (current.busy || current.receiving || current.preparingFiles) current
            else current.copy(mode = mode, p2pHost = if (mode == Mode.SEND && current.p2pConnected && !current.p2pIsOwner)
                current.p2pOwnerAddress else null)
        }
    }
    fun setOverride(profile: SecurityProfile?) { if (!state.value.busy) _state.update { it.copy(override = profile) } }
    fun setUserSaysPublic(value: Boolean) { if (!state.value.busy) { _state.update { it.copy(userSaysPublic = value) }; refreshContext() } }
    fun addFiles(uris: List<Uri>) {
        if (uris.isEmpty() || state.value.busy || state.value.receiving || state.value.preparingFiles) return
        _state.update { it.copy(preparingFiles = true) }
        scope.launch(Dispatchers.IO) {
            try {
                val picked = uris.take(TransferLimits.MAX_FILES).mapNotNull { uri ->
                    runCatching {
                        runCatching { app.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION) }
                        telemetry.describe(uri)
                    }.onFailure { log("Could not read selected file: ${it.message}") }.getOrNull()
                }
                _state.update { current ->
                    if (current.busy) current else {
                        val files = (current.files + picked).distinctBy { it.uri }.take(TransferLimits.MAX_FILES)
                        val net = telemetry.network(current.p2pConnected, current.userSaysPublic)
                        val dev = telemetry.device(net)
                        current.copy(files = files, assessments = files.map { ContextAnalyzer.assess(it.facts, dev) })
                    }
                }
            } finally { _state.update { it.copy(preparingFiles = false) } }
        }
    }
    fun clearFiles() {
        if (state.value.busy || state.value.preparingFiles) return
        val oldFiles = state.value.files
        _state.update { it.copy(files = emptyList(), assessments = emptyList()) }
        identities.clear()
        scope.launch(Dispatchers.IO) { oldFiles.forEach { telemetry.discardStaged(it.uri) } }
    }
    fun clearPartialFiles() {
        if (state.value.busy || state.value.receiving) return
        scope.launch(Dispatchers.IO) {
            runCatching { checkpoints.clear() }.onSuccess { log("Saved partial transfers deleted") }
                .onFailure { log("Could not clear partial transfers: ${it.message}") }
        }
    }
    fun onP2pStatus(message: String) { _state.update { it.copy(p2pStatus = message) }; log(message) }
    fun onP2pConnection(groupFormed: Boolean, isGroupOwner: Boolean, ownerAddress: String?) {
        _state.update { current ->
            current.copy(p2pConnected = groupFormed, p2pIsOwner = isGroupOwner,
                p2pOwnerAddress = if (groupFormed) ownerAddress else null,
                p2pHost = if (groupFormed && !isGroupOwner && current.mode == Mode.SEND) ownerAddress else null,
                p2pStatus = if (!groupFormed) "Wi-Fi Direct disconnected" else if (isGroupOwner)
                    "Wi-Fi Direct connected · this phone hosts the group" else "Wi-Fi Direct connected · group at $ownerAddress")
        }
        refreshContext()
    }

    private fun beginService(): Boolean = try {
        ContextCompat.startForegroundService(app, Intent(app, TransferService::class.java))
        true
    } catch (e: Exception) {
        fail(e)
        _state.update { it.copy(busy = false, receiving = false, progressIndeterminate = false) }
        false
    }

    /** Snapshot telemetry and files before opening the socket. Manual controls only raise security. */
    @Synchronized fun send(hostInput: String, password: CharArray?): String? {
        val current = state.value
        if (current.busy || current.receiving) return "Stop the current transfer or receiver first"
        if (current.preparingFiles) return "Wait for the selected files to finish preparing"
        if (current.files.isEmpty()) return "Choose at least one file"
        val reverse = current.p2pConnected && current.p2pIsOwner
        val host = hostInput.trim()
        if (!reverse && (!InetAddresses.isNumericAddress(host) || runCatching { InetAddress.getByName(host).isAnyLocalAddress }.getOrDefault(true)))
            return "Enter the receiver's numeric IP address shown on the other phone"
        val net = telemetry.network(current.p2pConnected, current.userSaysPublic)
        val dev = telemetry.device(net)
        val assessments = current.files.map { ContextAnalyzer.assess(it.facts, dev) }
        _state.update { it.copy(network = net, device = dev, assessments = assessments) }
        val needsPassword = assessments.any { current.profileFor(it).requiresPassword }
        if (needsPassword && (password == null || password.size !in 8..1024)) return "Maximum requires a shared password of 8–1024 characters"
        val files = current.files.zip(assessments).map { (picked, assessment) ->
            val id = identities.getOrPut(picked.uri) { Crypto.random(16) }
            OutgoingFile(picked.facts.name, picked.facts.mimeType ?: "application/octet-stream", picked.facts.sizeBytes,
                current.profileFor(assessment), id) {
                app.contentResolver.openInputStream(picked.uri) ?: throw IOException("Cannot open ${picked.facts.name}")
            }
        }
        if (files.sumOf { it.size } > TransferLimits.MAX_BATCH_BYTES) return "Choose a smaller batch of files"
        val pw = password?.takeIf { needsPassword }
        if (!needsPassword) password?.fill('\u0000')
        cancelled.set(false)
        _state.update { it.copy(busy = true, failed = false, verificationCode = null, verificationPending = false,
            progress = 0, progressIndeterminate = true, progressLabel = if (reverse) "Waiting for the receiver to join this group…" else "Connecting to $host…") }
        if (!beginService()) { pw?.fill('\u0000'); return "Cannot start a foreground transfer; keep the app visible and retry" }
        job = scope.launch(Dispatchers.IO) {
            try {
                val socket = if (reverse) acceptSocket() else connect(host)
                socket.use {
                    activeSocket = it
                    configure(it)
                    val (input, output) = TransferEngine.streams(it)
                    val result = TransferEngine.send(input, output, files, pw, uiListener(files.sumOf { f -> f.size }))
                    log("Delivered ${result.files.size} file(s), ${ContextAnalyzer.formatBytes(result.bytes)}; authenticated receiver receipt received")
                    _state.update { s -> s.copy(progress = 1000, progressLabel = "All files delivered and verified ✓", failed = false) }
                }
            } catch (e: Exception) { if (!cancelled.get()) fail(e) }
            finally {
                pw?.fill('\u0000'); activeSocket = null
                _state.update { it.copy(busy = false, progressIndeterminate = false, verificationPending = false) }
            }
        }
        return null
    }

    @Synchronized fun startReceiving() {
        if (state.value.busy || state.value.receiving || state.value.preparingFiles) return
        cancelled.set(false)
        _state.update { it.copy(receiving = true, failed = false, verificationCode = null, progress = 0,
            progressIndeterminate = true, progressLabel = "Ready to receive · port ${TransferEngine.DEFAULT_PORT}") }
        if (!beginService()) return
        job = scope.launch(Dispatchers.IO) {
            try {
                storageReady.await()
                checkpoints.cleanup()
                val socket = waitForSender()
                socket.use {
                    activeSocket = it; configure(it)
                    _state.update { s -> s.copy(busy = true, progressLabel = "Sender connected; establishing secure session…") }
                    val (input, output) = TransferEngine.streams(it)
                    val result = TransferEngine.receive(input, output,
                        sinks = { name, mime, size ->
                            if (app.getExternalFilesDir(null)?.usableSpace?.let { free -> free < size + 4L * 1024 * 1024 } == true)
                                throw IOException("Not enough free device storage")
                            DownloadsSink(app.contentResolver, name, mime)
                        },
                        passwords = { file, attempt -> askPassword(file, attempt) },
                        listener = uiListener(null), resumeStore = checkpoints)
                    log("Received ${result.files.size} verified file(s): ${result.files.joinToString()}")
                    _state.update { s -> s.copy(progress = 1000, progressLabel = "Verified files saved to Downloads/SecureTransfer ✓", failed = false) }
                }
            } catch (e: Exception) { if (!cancelled.get()) fail(e) }
            finally {
                activeSocket = null
                runCatching { serverSocket?.close() }; serverSocket = null
                if (cancelled.get()) runCatching { checkpoints.clear() }
                _state.update { it.copy(busy = false, receiving = false, progressIndeterminate = false, verificationPending = false) }
            }
        }
    }

    private fun configure(socket: Socket) { socket.soTimeout = 180_000; socket.tcpNoDelay = true }
    private fun connect(host: String): Socket {
        val socket = Socket(); activeSocket = socket
        try {
            if (cancelled.get()) throw CancellationException()
            socket.connect(InetSocketAddress(host, TransferEngine.DEFAULT_PORT), 10_000)
            return socket
        } catch (e: Exception) { socket.close(); throw e }
    }
    private fun acceptSocket(): Socket = ServerSocket().use { server ->
        serverSocket = server; server.reuseAddress = true; server.soTimeout = 1000
        server.bind(InetSocketAddress(TransferEngine.DEFAULT_PORT))
        val deadline = SystemClock.elapsedRealtime() + 120_000
        while (!cancelled.get() && SystemClock.elapsedRealtime() < deadline) {
            try { return server.accept() } catch (_: SocketTimeoutException) { /* bounded cancellation polling */ }
        }
        throw SocketTimeoutException("Receiver did not connect within two minutes")
    }

    /** Group-owner negotiation is independent of file direction: either phone can host TCP. */
    private fun waitForSender(): Socket {
        val deadline = SystemClock.elapsedRealtime() + 120_000
        var server: ServerSocket? = null
        try {
            while (!cancelled.get() && SystemClock.elapsedRealtime() < deadline) {
                val current = state.value
                if (current.p2pConnected && !current.p2pIsOwner && current.p2pOwnerAddress != null) {
                    server?.close(); server = null; serverSocket = null
                    try { return connect(current.p2pOwnerAddress) }
                    catch (e: IOException) {
                        if (cancelled.get()) throw e
                        // The sender opens its listening socket when Encrypt & send is pressed.
                        runBlocking { delay(800) }
                    }
                } else {
                    if (server == null) {
                        server = ServerSocket().apply {
                            reuseAddress = true; soTimeout = 1000
                            bind(InetSocketAddress(TransferEngine.DEFAULT_PORT))
                        }
                        serverSocket = server
                    }
                    try { return server.accept() } catch (_: SocketTimeoutException) { }
                }
            }
            throw SocketTimeoutException("No sender connected. Tap Start receiving to try again.")
        } finally { server?.close(); serverSocket = null }
    }

    private fun askPassword(file: String, attempt: Int): CharArray? = runBlocking {
        val request = PasswordRequest(file, attempt, CompletableDeferred())
        _passwordRequest.value = request
        try { withTimeoutOrNull(120_000) { request.answer.await() } }
        finally { _passwordRequest.value = null }
    }
    private fun confirmCode(code: String): Boolean = runBlocking {
        val request = VerificationRequest(code, CompletableDeferred())
        _verificationRequest.value = request
        _state.update { it.copy(verificationPending = true, progressLabel = "Compare $code on both phones and confirm") }
        try { withTimeoutOrNull(120_000) { request.answer.await() } ?: false }
        finally { _verificationRequest.value = null; _state.update { it.copy(verificationPending = false) } }
    }
    fun stopReceiving() = cancelAll()
    fun cancel() = cancelAll()
    fun cancelAll(message: String = "Cancelled. Incomplete incoming files discarded.") {
        if (!state.value.busy && !state.value.receiving) return
        if (!cancelled.compareAndSet(false, true)) return
        _passwordRequest.value?.answer?.complete(null)
        _verificationRequest.value?.answer?.complete(false)
        runCatching { activeSocket?.close() }
        runCatching { serverSocket?.close() }
        // Let the worker run finally blocks and erase checkpoints before allowing another transfer.
        _state.update { it.copy(progressLabel = message, progressIndeterminate = false) }
    }

    private fun uiListener(batchBytes: Long?) = object : TransferListener {
        private var lastUpdate = 0L
        private var name = ""
        private var profile = SecurityProfile.STANDARD
        private var count = 0
        private var completed = 0L
        private var previousIndex = -1
        private var previousSize = 0L
        private var startBytes = 0L
        private var startTime = 0L
        override fun isCancelled() = cancelled.get()
        override fun onVerificationCode(code: String) { _state.update { it.copy(verificationCode = code) } }
        override fun confirmVerification(code: String) = confirmCode(code)
        override fun onLog(message: String) = log(message)
        override fun onFileStarted(index: Int, total: Int, name: String, profile: SecurityProfile, size: Long) {
            if (previousIndex >= 0) completed += previousSize
            previousIndex = index; previousSize = size
            this.name = name; this.profile = profile; count = total
            startTime = 0L; startBytes = 0L
            _state.update { it.copy(progressIndeterminate = true, progressLabel = "File ${index + 1}/$total · $name · ${profile.displayName} · preparing…") }
        }
        override fun onProgress(index: Int, bytesDone: Long, size: Long) {
            val now = SystemClock.elapsedRealtime()
            if (startTime == 0L) { startTime = now; startBytes = bytesDone }
            if (now - lastUpdate < 150 && bytesDone != size) return
            lastUpdate = now
            val fraction = if (batchBytes != null && batchBytes > 0) (completed + bytesDone).toDouble() / batchBytes
                else if (size > 0) bytesDone.toDouble() / size else 1.0
            val speed = if (now > startTime) ContextAnalyzer.formatBytes((bytesDone - startBytes) * 1000 / (now - startTime)) + "/s" else "measuring speed…"
            _state.update { it.copy(progress = (fraction * 1000).toInt().coerceIn(0, 1000), progressIndeterminate = false,
                progressLabel = "File ${index + 1}/$count · $name\n${profile.displayName} · ${ContextAnalyzer.formatBytes(bytesDone)} / ${ContextAnalyzer.formatBytes(size)} · $speed") }
        }
        override fun onFileFinished(index: Int, name: String, location: String?) {
            log(if (location != null) "Saved: $name → $location" else "Delivered: $name")
        }
    }
    private fun fail(error: Throwable) {
        val message = when (error) {
            is IntegrityException -> "Authentication/integrity check failed. Invalid partial data discarded. ${error.message}"
            is SocketTimeoutException -> "Connection timed out. Keep both phones on the same network and retry. Verified encrypted chunks are retained."
            is ConnectException -> "Receiver unreachable. Start receiving on the other phone; check IP, Wi-Fi and hotspot isolation."
            is IOException -> "Connection or storage interrupted: ${error.message}. Reconnect and retry the same files to resume."
            is ProtocolException -> error.message ?: "Secure protocol rejected this transfer"
            else -> error.message ?: error.javaClass.simpleName
        }
        log("Failed: $message")
        _state.update { it.copy(progressLabel = message, failed = true, progressIndeterminate = false) }
    }
    fun log(message: String) {
        val line = "${LocalTime.now().format(TIME)}  $message"
        _state.update { it.copy(log = (it.log + line).takeLast(120)) }
    }
    private companion object { val TIME: DateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss", Locale.US) }
}
