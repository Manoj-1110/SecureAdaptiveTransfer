package com.wmc.securetransfer

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.net.Uri
import android.net.wifi.p2p.WifiP2pDevice
import android.net.wifi.p2p.WifiP2pInfo
import android.os.Build
import android.os.Bundle
import android.text.Editable
import android.view.LayoutInflater
import android.view.View
import android.view.WindowManager
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.OnBackPressedCallback
import android.app.Dialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.content.IntentCompat
import androidx.core.view.WindowCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.button.MaterialButton
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import com.wmc.securetransfer.core.ContextAnalyzer
import com.wmc.securetransfer.core.SecurityProfile
import com.wmc.securetransfer.core.TransferEngine
import com.wmc.securetransfer.databinding.ActivityMainBinding
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity(), WifiDirectController.Callbacks {

    private lateinit var b: ActivityMainBinding
    private val vm get() = (application as TransferApplication).transfers
    private lateinit var p2p: WifiDirectController
    private var lastP2pHost: String? = null
    private var shownPasswordRequest: PasswordRequest? = null
    private var shownVerificationRequest: VerificationRequest? = null
    private var passwordDialog: Dialog? = null
    private var verificationDialog: Dialog? = null
    private var renderedFiles: List<PickedFile>? = null
    private var renderedAssessments: List<com.wmc.securetransfer.core.Assessment>? = null
    private var renderedOverride: SecurityProfile? = null
    private val notificationsPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { allowed ->
        if (!allowed) snack("Transfers can continue; enable notifications in Settings for background progress and cancellation.")
    }

    private val pickFiles = registerForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        vm.addFiles(uris)
    }

    private val p2pPermissions = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { result ->
        if (result.values.all { it }) p2p.discover()
        else snack("Nearby-device permission is needed to find phones over Wi-Fi Direct. You can still connect by IP.")
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityMainBinding.inflate(layoutInflater)
        setContentView(b.root)
        val lightMode = resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK != Configuration.UI_MODE_NIGHT_YES
        WindowCompat.getInsetsController(window, window.decorView).apply {
            isAppearanceLightStatusBars = lightMode
            isAppearanceLightNavigationBars = lightMode
        }
        p2p = WifiDirectController(this, this)

        b.modeGroup.addOnButtonCheckedListener { _, id, checked ->
            if (checked) vm.setMode(if (id == R.id.modeReceive) Mode.RECEIVE else Mode.SEND)
        }
        b.discoverButton.setOnClickListener { requestP2pAndDiscover() }
        b.disconnectButton.setOnClickListener { p2p.disconnect() }
        b.pickButton.setOnClickListener { pickFiles.launch(arrayOf("*/*")) }
        b.clearButton.setOnClickListener { vm.clearFiles() }
        b.publicSwitch.setOnCheckedChangeListener { _, v -> vm.setUserSaysPublic(v) }
        b.profileGroup.setOnCheckedStateChangeListener { _, ids ->
            vm.setOverride(
                when (ids.firstOrNull()) {
                    R.id.chipStandard -> SecurityProfile.STANDARD
                    R.id.chipEnhanced -> SecurityProfile.ENHANCED
                    R.id.chipMaximum -> SecurityProfile.MAXIMUM
                    else -> null
                },
            )
        }
        b.sendButton.setOnClickListener { onSend() }
        b.receiveButton.setOnClickListener {
            if (vm.state.value.receiving) vm.stopReceiving() else vm.startReceiving()
        }
        b.cancelButton.setOnClickListener { vm.cancel() }
        b.clearPartialButton.setOnClickListener { vm.clearPartialFiles() }
        if (Build.VERSION.SDK_INT >= 33 && savedInstanceState == null &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
            notificationsPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (vm.state.value.busy || vm.state.value.receiving) {
                    moveTaskToBack(true)
                } else { isEnabled = false; onBackPressedDispatcher.onBackPressed() }
            }
        })

        if (!p2p.available) b.discoverButton.isEnabled = false

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch { vm.state.collect(::render) }
                launch { vm.passwordRequest.collect { request ->
                    if (request == null) { passwordDialog?.dismiss(); passwordDialog = null; shownPasswordRequest = null }
                    else showPasswordDialog(request)
                } }
                launch { vm.verificationRequest.collect { request ->
                    if (request == null) { verificationDialog?.dismiss(); verificationDialog = null; shownVerificationRequest = null }
                    else showVerificationDialog(request)
                } }
            }
        }
        if (savedInstanceState == null) handleShareIntent(intent)
    }

    override fun onDestroy() {
        passwordDialog?.dismiss()
        verificationDialog?.dismiss()
        p2p.close()
        super.onDestroy()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleShareIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        p2p.register()
        vm.refreshContext()
    }

    override fun onPause() {
        p2p.unregister()
        super.onPause()
    }

    private fun handleShareIntent(intent: Intent?) {
        val uris: List<Uri> = when (intent?.action) {
            Intent.ACTION_SEND -> listOfNotNull(IntentCompat.getParcelableExtra(intent, Intent.EXTRA_STREAM, Uri::class.java))
            Intent.ACTION_SEND_MULTIPLE -> IntentCompat.getParcelableArrayListExtra(intent, Intent.EXTRA_STREAM, Uri::class.java).orEmpty()
            else -> emptyList()
        }
        if (uris.isNotEmpty()) {
            b.modeGroup.check(R.id.modeSend)
            vm.addFiles(uris)
        }
    }

    // ---------------------------------------------------------------- render

    private fun render(s: UiState) {
        val sending = s.mode == Mode.SEND
        val modeId = if (sending) R.id.modeSend else R.id.modeReceive
        if (b.modeGroup.checkedButtonId != modeId) b.modeGroup.check(modeId)
        b.modeSend.isEnabled = !s.busy && !s.receiving && !s.preparingFiles
        b.modeReceive.isEnabled = !s.busy && !s.receiving && !s.preparingFiles
        if (b.publicSwitch.isChecked != s.userSaysPublic) b.publicSwitch.isChecked = s.userSaysPublic
        val profileId = when (s.override) {
            SecurityProfile.STANDARD -> R.id.chipStandard
            SecurityProfile.ENHANCED -> R.id.chipEnhanced
            SecurityProfile.MAXIMUM -> R.id.chipMaximum
            null -> R.id.chipAuto
        }
        if (b.profileGroup.checkedChipId != profileId) b.profileGroup.check(profileId)
        listOf(b.chipAuto, b.chipStandard, b.chipEnhanced, b.chipMaximum).forEach { it.isEnabled = !s.busy }
        b.publicSwitch.isEnabled = !s.busy
        b.hostInput.isEnabled = !s.busy
        b.clearButton.isEnabled = !s.busy && !s.preparingFiles
        b.clearPartialButton.isEnabled = !s.busy && !s.receiving
        b.discoverButton.isEnabled = p2p.available && !s.busy
        b.disconnectButton.isEnabled = !s.busy
        b.sendCard.visibility = if (sending) View.VISIBLE else View.GONE
        b.receiveCard.visibility = if (sending) View.GONE else View.VISIBLE
        b.hostLayout.visibility = if (sending) View.VISIBLE else View.GONE

        // Connection
        b.p2pStatus.text = s.p2pStatus
        b.disconnectButton.visibility = if (s.p2pConnected) View.VISIBLE else View.GONE
        if (s.p2pHost != null && s.p2pHost != lastP2pHost) b.hostInput.setText(s.p2pHost)
        lastP2pHost = s.p2pHost
        b.myAddress.text = if (!sending && s.myAddresses.isNotEmpty())
            "This phone: " + s.myAddresses.joinToString(", ") + " · port ${TransferEngine.DEFAULT_PORT}" else ""

        // Context summary
        val dev = s.device
        b.contextSummary.text = buildString {
            append("Network: ").append(s.network?.description ?: "…")
            append("\nSensitivity uses metadata estimates. Raise the profile if the contents are sensitive.")
            if (dev != null) {
                append("\nBattery: ${dev.batteryPercent}%")
                if (dev.isCharging) append(" (charging)")
                if (dev.thermalStressed) append(" · thermal throttling")
            }
        }

        // Files with per-file profile and reasons
        if (renderedFiles != s.files || renderedAssessments != s.assessments || renderedOverride != s.override) {
        b.fileList.removeAllViews()
        if (s.files.isEmpty()) {
            b.fileList.addView(TextView(this).apply { text = getString(R.string.no_files); setTextColor(getColor(R.color.muted)); setPadding(0, 12, 0, 0) })
        }
        s.files.forEachIndexed { i, f ->
            val a = s.assessments.getOrNull(i)
            val profile = a?.let { s.profileFor(it) }
            b.fileList.addView(fileRow(f, profile, a?.reasons.orEmpty(), overridden = s.override != null))
        }

            renderedFiles = s.files
            renderedAssessments = s.assessments
            renderedOverride = s.override
        }

        b.passwordLayout.visibility = if (s.needsPassword) View.VISIBLE else View.GONE
        b.sendButton.isEnabled = !s.busy && !s.receiving && !s.preparingFiles && s.files.isNotEmpty() && s.assessments.size == s.files.size
        b.sendButton.text = if (s.failed) "Retry encrypted transfer" else getString(R.string.send)
        b.pickButton.isEnabled = !s.busy && !s.preparingFiles

        // Receive
        b.receiveButton.text = getString(if (s.receiving) R.string.stop_receiving else R.string.start_receiving)
        b.receiveInfo.text = if (s.receiving)
            "Ready for two minutes. Connect over Wi-Fi Direct or enter this phone’s Wi-Fi IP on the sender. Confirm matching codes on both phones. Verified files appear in Downloads/SecureTransfer."
        else "Tap Start, then send from the other phone."

        // Status
        b.verificationCode.text = s.verificationCode ?: "— — —"
        val indeterminate = s.progressIndeterminate || s.preparingFiles
        if (b.progress.isIndeterminate != indeterminate) b.progress.isIndeterminate = indeterminate
        if (!indeterminate) b.progress.setProgressCompat(s.progress, true)
        b.progressLabel.text = if (s.preparingFiles) "Reading file metadata and staging unknown-size documents…" else s.progressLabel
        b.cancelButton.visibility = if (s.busy || s.receiving) View.VISIBLE else View.GONE
        b.log.text = s.log.takeLast(40).joinToString("\n")


    }

    private fun fileRow(f: PickedFile, profile: SecurityProfile?, reasons: List<String>, overridden: Boolean): View {
        val row = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(0, 16, 0, 8) }
        row.addView(TextView(this).apply {
            text = getString(R.string.file_description, f.facts.name, ContextAnalyzer.formatBytes(f.facts.sizeBytes))
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyLarge)
        })
        if (profile != null) {
            val color = when (profile) {
                SecurityProfile.STANDARD -> R.color.profile_standard
                SecurityProfile.ENHANCED -> R.color.profile_enhanced
                SecurityProfile.MAXIMUM -> R.color.profile_maximum
            }
            row.addView(TextView(this).apply {
                text = getString(R.string.profile_description, profile.displayName, profile.chunkLabel,
                    profile.rotationLabel, if (overridden) getString(R.string.manual_minimum) else "")
                setTextColor(getColor(color))
                setTypeface(typeface, android.graphics.Typeface.BOLD)
            })
            row.addView(TextView(this).apply {
                text = reasons.joinToString("\n") { "• $it" }
                textSize = 12f
                setTextColor(getColor(R.color.muted))
            })
        }
        return row
    }

    // ----------------------------------------------------------------- actions

    private fun onSend() {
        val pwText: Editable? = b.passwordInput.text
        val password = pwText?.let { CharArray(it.length).also { arr -> it.getChars(0, it.length, arr, 0) } }
        val error = vm.send(b.hostInput.text?.toString().orEmpty(), password)
        if (error != null) {
            password?.fill('\u0000')
            snack(error)
        } else {
            pwText?.clear()
        }
    }

    private fun requestP2pAndDiscover() {
        val perms = if (Build.VERSION.SDK_INT >= 33) arrayOf(Manifest.permission.NEARBY_WIFI_DEVICES)
        else arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION)
        if (perms.all { ContextCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_GRANTED }) p2p.discover()
        else p2pPermissions.launch(perms)
    }

    private fun showPasswordDialog(req: PasswordRequest) {
        if (req === shownPasswordRequest) return
        shownPasswordRequest = req
        val layout = TextInputLayout(this).apply {
            hint = getString(R.string.enter_password)
            endIconMode = TextInputLayout.END_ICON_PASSWORD_TOGGLE
            setPadding(48, 16, 48, 0)
            if (req.attempt > 1) error = "Wrong password – attempt ${req.attempt} of 3"
        }
        val input = TextInputEditText(layout.context).apply {
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        layout.addView(input)
        passwordDialog = MaterialAlertDialogBuilder(this)
            .setTitle("Protected file")
            .setMessage("\"${req.fileName}\" was sent with the Maximum profile. Enter the password the sender told you.")
            .setView(layout)
            .setCancelable(false)
            .setPositiveButton("Unlock") { _, _ ->
                val t = input.text
                val chars = t?.let { CharArray(it.length).also { arr -> it.getChars(0, it.length, arr, 0) } }
                t?.clear()
                req.answer.complete(chars?.takeIf { it.isNotEmpty() })
            }
            .setNegativeButton(R.string.cancel) { _, _ -> req.answer.complete(null) }
            .show()
    }

    private fun showVerificationDialog(request: VerificationRequest) {
        if (request === shownVerificationRequest) return
        shownVerificationRequest = request
        verificationDialog = MaterialAlertDialogBuilder(this)
            .setTitle("Compare codes: ${request.code}")
            .setMessage("Read the six digits on the other phone. Tap Codes match on BOTH phones only when they are identical. If they differ, cancel the connection.")
            .setCancelable(false)
            .setPositiveButton("Codes match") { _, _ -> request.answer.complete(true) }
            .setNegativeButton("Reject connection") { _, _ -> request.answer.complete(false) }
            .show()
    }

    private fun snack(msg: String) = Snackbar.make(b.root, msg, Snackbar.LENGTH_LONG).show()

    // ------------------------------------------------- Wi-Fi Direct callbacks

    override fun onPeers(peers: List<WifiP2pDevice>) {
        b.peerList.removeAllViews()
        peers.forEach { d ->
            val btn = LayoutInflater.from(this).inflate(R.layout.item_peer, b.peerList, false) as MaterialButton
            btn.text = getString(R.string.peer_description, d.deviceName.ifBlank { d.deviceAddress }, statusName(d.status))
            btn.isEnabled = !vm.state.value.busy
            btn.setOnClickListener { if (!vm.state.value.busy) p2p.connect(d, asReceiver = vm.state.value.mode == Mode.RECEIVE) }
            b.peerList.addView(btn)
        }
        if (peers.isEmpty()) vm.onP2pStatus("No devices found yet – open the app on the other phone and tap Find too")
    }

    override fun onConnection(info: WifiP2pInfo?) {
        vm.onP2pConnection(
            groupFormed = info?.groupFormed == true,
            isGroupOwner = info?.isGroupOwner == true,
            ownerAddress = info?.groupOwnerAddress?.hostAddress,
        )
    }

    override fun onStatus(message: String) = vm.onP2pStatus(message)

    private fun statusName(s: Int) = when (s) {
        WifiP2pDevice.AVAILABLE -> "available"
        WifiP2pDevice.INVITED -> "invited"
        WifiP2pDevice.CONNECTED -> "connected"
        WifiP2pDevice.FAILED -> "failed"
        else -> "unavailable"
    }
}
