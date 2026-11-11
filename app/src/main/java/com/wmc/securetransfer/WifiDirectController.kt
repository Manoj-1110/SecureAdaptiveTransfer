package com.wmc.securetransfer

import android.annotation.SuppressLint
import android.Manifest
import android.content.pm.PackageManager
import android.location.LocationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.wifi.WpsInfo
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pDevice
import android.net.wifi.p2p.WifiP2pInfo
import android.net.wifi.p2p.WifiP2pManager
import android.os.Build
import androidx.core.content.ContextCompat

/**
 * Thin wrapper around [WifiP2pManager] for discovery and connection.
 * The receiver prefers group ownership. The transfer coordinator handles either
 * negotiated owner and learns its address from the platform.
 */
class WifiDirectController(private val context: Context, private val callbacks: Callbacks) {

    interface Callbacks {
        fun onPeers(peers: List<WifiP2pDevice>)
        fun onConnection(info: WifiP2pInfo?)
        fun onStatus(message: String)
    }

    @Volatile private var closed = false
    private val manager: WifiP2pManager? = context.getSystemService(WifiP2pManager::class.java)
    private val channel: WifiP2pManager.Channel? = runCatching {
        manager?.initialize(context, context.mainLooper) {
            if (!closed) callbacks.onStatus("Wi-Fi Direct channel closed. Reopen the app to reconnect.")
        }
    }.getOrNull()
    private var registered = false
    private fun hasPermission(): Boolean = ContextCompat.checkSelfPermission(context,
        if (Build.VERSION.SDK_INT >= 33) Manifest.permission.NEARBY_WIFI_DEVICES else Manifest.permission.ACCESS_FINE_LOCATION,
    ) == PackageManager.PERMISSION_GRANTED
    val available get() = manager != null && channel != null

    private val receiver = object : BroadcastReceiver() {
        @SuppressLint("MissingPermission")
        override fun onReceive(ctx: Context, intent: Intent) {
            if (closed) return
            when (intent.action) {
                WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION -> {
                    val enabled = intent.getIntExtra(WifiP2pManager.EXTRA_WIFI_STATE, -1) == WifiP2pManager.WIFI_P2P_STATE_ENABLED
                    if (!enabled) callbacks.onStatus("Wi-Fi Direct is off – turn on Wi-Fi")
                }
                WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION ->
                    runCatching { manager?.requestPeers(channel) { list -> if (!closed) callbacks.onPeers(list?.deviceList?.toList().orEmpty()) } }
                WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION -> {
                    runCatching { manager?.requestConnectionInfo(channel) { info ->
                        if (!closed) callbacks.onConnection(info?.takeIf { it.groupFormed })
                    } }.onFailure { callbacks.onStatus("Cannot read Wi-Fi Direct connection: ${it.message}") }
                }
            }
        }
    }

    fun register() {
        if (!available || registered || closed) return
        val filter = IntentFilter().apply {
            addAction(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION)
        }
        ContextCompat.registerReceiver(context, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
        registered = true
        if (hasPermission()) try {
            manager?.requestConnectionInfo(channel) { if (!closed) callbacks.onConnection(it) }
            manager?.requestPeers(channel) { if (!closed) callbacks.onPeers(it.deviceList.toList()) }
        } catch (_: SecurityException) { callbacks.onStatus("Nearby-device permission was revoked") }
    }

    fun unregister() {
        if (registered) { runCatching { context.unregisterReceiver(receiver) }; registered = false }
    }

    fun close() { closed = true; unregister(); channel?.close() }

    @SuppressLint("MissingPermission")
    fun discover() {
        val m = manager ?: return callbacks.onStatus("This device has no Wi-Fi Direct")
        if (!hasPermission()) return callbacks.onStatus("Grant Nearby devices permission (Location on Android 10–12) to discover phones")
        if (Build.VERSION.SDK_INT < 33 && context.getSystemService(LocationManager::class.java)?.isLocationEnabled == false)
            return callbacks.onStatus("Enable Location in Android Settings to discover nearby Wi-Fi Direct devices")
        runCatching { m.discoverPeers(channel, action("Searching for nearby devices…", "Discovery failed")) }
            .onFailure { callbacks.onStatus("Cannot discover devices: ${it.message}") }
    }

    /** [asReceiver] = true asks to become group owner so the sender knows where to connect. */
    @SuppressLint("MissingPermission")
    fun connect(device: WifiP2pDevice, asReceiver: Boolean) {
        val config = WifiP2pConfig().apply {
            deviceAddress = device.deviceAddress
            wps.setup = WpsInfo.PBC
            groupOwnerIntent = if (asReceiver) 15 else 0
        }
        if (!hasPermission()) return callbacks.onStatus("Nearby-device permission is required to connect")
        runCatching {
            manager?.connect(channel, config, action("Connecting to ${device.deviceName}… accept the prompt on the other phone", "Connection failed"))
        }.onFailure { callbacks.onStatus("Cannot connect: ${it.message}") }
    }

    fun disconnect() {
        runCatching { manager?.removeGroup(channel, action("Disconnected", "Nothing to disconnect")) }
            .onFailure { callbacks.onStatus("Cannot disconnect: ${it.message}") }
    }

    private fun action(ok: String, fail: String) = object : WifiP2pManager.ActionListener {
        override fun onSuccess() = callbacks.onStatus(ok)
        override fun onFailure(reason: Int) = callbacks.onStatus(
            "$fail (" + when (reason) {
                WifiP2pManager.P2P_UNSUPPORTED -> "Wi-Fi Direct unsupported"
                WifiP2pManager.BUSY -> "system busy, try again"
                else -> "error $reason"
            } + ")",
        )
    }
}
