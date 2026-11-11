package com.wmc.securetransfer

import android.content.ContentResolver
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Network
import android.net.NetworkRequest
import java.util.concurrent.ConcurrentHashMap
import android.net.Uri
import android.net.wifi.WifiInfo
import android.os.BatteryManager
import android.os.Build
import android.os.Environment
import android.os.PowerManager
import android.os.Bundle
import android.content.ContentUris
import android.provider.MediaStore
import android.provider.OpenableColumns
import com.wmc.securetransfer.core.DeviceContext
import com.wmc.securetransfer.core.FileFacts
import com.wmc.securetransfer.core.IncomingSink
import com.wmc.securetransfer.core.NetworkRisk
import com.wmc.securetransfer.core.TransferLimits
import java.io.File
import java.io.OutputStream
import java.net.Inet4Address
import java.net.NetworkInterface

/** A file the user picked, with metadata read from the content provider. */
data class PickedFile(val uri: Uri, val facts: FileFacts)

/** Reads device telemetry for the context analyzer. Only metadata – never file contents. */
class Telemetry(private val context: Context) {
    private val wifiCapabilities = ConcurrentHashMap<Network, NetworkCapabilities>()

    /** Keep local Wi-Fi context even if cellular is the default internet route. */
    fun observeLocalWifi(onChanged: () -> Unit) {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        manager.registerNetworkCallback(NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI).build(),
            object : ConnectivityManager.NetworkCallback() {
                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                    wifiCapabilities[network] = caps
                    onChanged()
                }
                override fun onLost(network: Network) { wifiCapabilities.remove(network); onChanged() }
            })
    }

    data class NetworkReading(val risk: NetworkRisk, val description: String)

    /**
     * Risk of the link the transfer will use.
     * - Wi-Fi Direct groups are WPA2-protected point-to-point links → trusted.
     * - Wi-Fi: open / OWE / captive-portal networks are public; WPA2/WPA3 networks are trusted
     *   unless the user marks them public.
     * - Cellular → cellular.
     */
    fun network(overWifiDirect: Boolean, userSaysPublic: Boolean): NetworkReading {
        if (userSaysPublic) return NetworkReading(NetworkRisk.UNTRUSTED, "Network marked public by you")
        if (overWifiDirect) return NetworkReading(NetworkRisk.TRUSTED, "Wi-Fi Direct (WPA2 peer-to-peer group)")

        val cm = context.getSystemService(ConnectivityManager::class.java)
        // A local Wi-Fi link can coexist with cellular as the system's default internet network.
        val caps = wifiCapabilities.values.firstOrNull() ?: cm?.getNetworkCapabilities(cm.activeNetwork)
            ?: return NetworkReading(NetworkRisk.UNTRUSTED, "Local link with unknown network security")

        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> {
                if (userSaysPublic) return NetworkReading(NetworkRisk.UNTRUSTED, "Wi-Fi marked public by you")
                if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL))
                    return NetworkReading(NetworkRisk.UNTRUSTED, "Wi-Fi with captive portal (public hotspot)")
                val security = wifiSecurity(caps)
                when (security) {
                    WifiSecurity.OPEN -> NetworkReading(NetworkRisk.UNTRUSTED, "Open Wi-Fi (no password)")
                    WifiSecurity.SECURED -> NetworkReading(NetworkRisk.TRUSTED, "Password-protected Wi-Fi")
                    WifiSecurity.UNKNOWN -> NetworkReading(NetworkRisk.UNTRUSTED, "Wi-Fi security unavailable; conservative protection")
                }
            }
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetworkReading(NetworkRisk.CELLULAR, "Cellular data")
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> NetworkReading(NetworkRisk.TRUSTED, "Ethernet")
            else -> NetworkReading(NetworkRisk.UNTRUSTED, "Unknown network type")
        }
    }

    private enum class WifiSecurity { OPEN, SECURED, UNKNOWN }

    private fun wifiSecurity(caps: NetworkCapabilities): WifiSecurity {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return WifiSecurity.UNKNOWN
        val info = caps.transportInfo as? WifiInfo ?: return WifiSecurity.UNKNOWN
        return when (info.currentSecurityType) {
            WifiInfo.SECURITY_TYPE_OPEN, WifiInfo.SECURITY_TYPE_OWE -> WifiSecurity.OPEN
            WifiInfo.SECURITY_TYPE_UNKNOWN -> WifiSecurity.UNKNOWN
            else -> WifiSecurity.SECURED
        }
    }

    fun device(network: NetworkReading): DeviceContext {
        val battery = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        val level = battery?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = battery?.getIntExtra(BatteryManager.EXTRA_SCALE, 100) ?: 100
        val pct = if (level >= 0 && scale > 0) level * 100 / scale else 100
        val status = battery?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1
        val charging = status == BatteryManager.BATTERY_STATUS_CHARGING || status == BatteryManager.BATTERY_STATUS_FULL
        val pm = context.getSystemService(PowerManager::class.java)
        val thermal = (pm?.currentThermalStatus ?: 0) >= PowerManager.THERMAL_STATUS_SEVERE
        return DeviceContext(network.risk, pct, charging, thermal)
    }

    /** Resolves name/size/MIME for a content Uri. Files with unknown size are copied to cache first. */
    fun describe(uri: Uri): PickedFile {
        val cr = context.contentResolver
        var name: String? = null
        var size: Long? = null
        cr.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                c.getColumnIndex(OpenableColumns.DISPLAY_NAME).takeIf { it >= 0 && !c.isNull(it) }?.let { name = c.getString(it) }
                c.getColumnIndex(OpenableColumns.SIZE).takeIf { it >= 0 && !c.isNull(it) }?.let { size = c.getLong(it) }
            }
        }
        val mime = cr.getType(uri) ?: "application/octet-stream"
        val displayName = name ?: uri.lastPathSegment?.substringAfterLast('/') ?: "file"
        val knownSize = size
        if (knownSize != null && knownSize >= 0) {
            require(knownSize <= TransferLimits.MAX_FILE_BYTES) { "File exceeds the 64 GiB protocol limit" }
            return PickedFile(uri, FileFacts(displayName.take(240), mime.take(128), knownSize))
        }

        // Size unknown (some providers): stage a private copy so the declared size is exact.
        val staged = File(context.cacheDir, "staged_${System.nanoTime()}")
        try {
            cr.openInputStream(uri)?.use { input ->
                staged.outputStream().use { output ->
                    val buffer = ByteArray(256 * 1024)
                    var total = 0L
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        check(count > 0) { "Provider stopped producing data" }
                        total += count
                        check(total <= TransferLimits.MAX_FILE_BYTES && staged.parentFile!!.usableSpace > count + 4L * 1024 * 1024) {
                            "File is too large or private storage is full"
                        }
                        output.write(buffer, 0, count)
                    }
                    buffer.fill(0)
                }
            } ?: throw IllegalStateException("Cannot open $displayName")
            return PickedFile(Uri.fromFile(staged), FileFacts(displayName.take(240), mime.take(128), staged.length()))
        } catch (error: Exception) { staged.delete(); throw error }
    }

    fun discardStaged(uri: Uri) {
        if (uri.scheme == "file") {
            val file = File(uri.path ?: return)
            if (file.parentFile?.canonicalFile == context.cacheDir.canonicalFile && file.name.startsWith("staged_")) file.delete()
        }
    }

    fun cleanupStagedFiles() {
        val cutoff = System.currentTimeMillis() - 24L * 60 * 60 * 1000
        context.cacheDir.listFiles()?.filter { it.name.startsWith("staged_") && it.lastModified() < cutoff }?.forEach { it.delete() }
    }

    fun localIpv4Addresses(): List<String> = runCatching {
        NetworkInterface.getNetworkInterfaces().toList()
            .filter { it.isUp && !it.isLoopback }
            .flatMap { nif -> nif.inetAddresses.toList().filterIsInstance<Inet4Address>().map { "${it.hostAddress} (${nif.name})" } }
    }.getOrDefault(emptyList())
}

/**
 * Writes a received file into Downloads/SecureTransfer via MediaStore.
 * The entry stays IS_PENDING (invisible to other apps) until the SHA-256 check passes;
 * on any failure it is deleted.
 */
class DownloadsSink(private val resolver: ContentResolver, private val name: String, mime: String) : IncomingSink {
    private val uri: Uri = resolver.insert(
        MediaStore.Downloads.EXTERNAL_CONTENT_URI,
        ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, name)
            put(MediaStore.MediaColumns.MIME_TYPE, mime.ifBlank { "application/octet-stream" })
            put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/SecureTransfer/")
            put(MediaStore.MediaColumns.IS_PENDING, 1)
            put(MediaStore.MediaColumns.DATE_EXPIRES, System.currentTimeMillis() / 1000 + 24 * 60 * 60)
        },
    ) ?: throw IllegalStateException("Could not create $name in Downloads")
    private var stream: OutputStream? = try {
        resolver.openOutputStream(uri, "w")?.buffered(256 * 1024) ?: throw java.io.IOException("Cannot open pending download")
    } catch (error: Exception) { runCatching { resolver.delete(uri, null, null) }; throw error }
    private var published = false
    override val output: OutputStream get() = checkNotNull(stream) { "Pending output is closed" }
    override fun finishWriting() { stream?.close(); stream = null }
    override fun commit(): String {
        finishWriting()
        check(resolver.update(uri, ContentValues().apply {
            put(MediaStore.MediaColumns.IS_PENDING, 0)
            putNull(MediaStore.MediaColumns.DATE_EXPIRES)
        }, null, null) == 1) { "Could not publish verified download" }
        published = true
        return "Downloads/SecureTransfer/$name ($uri)"
    }
    override fun abort() {
        runCatching { stream?.close() }; stream = null
        if (!published) runCatching { resolver.delete(uri, null, null) }
    }
    companion object {
        fun cleanup(resolver: ContentResolver, packageName: String) {
            val selection = "${MediaStore.MediaColumns.OWNER_PACKAGE_NAME} = ? AND ${MediaStore.MediaColumns.IS_PENDING} = 1 AND ${MediaStore.MediaColumns.RELATIVE_PATH} = ?"
            val args = arrayOf(packageName, Environment.DIRECTORY_DOWNLOADS + "/SecureTransfer/")
            val collection = MediaStore.Downloads.EXTERNAL_CONTENT_URI
            val columns = arrayOf(MediaStore.MediaColumns._ID)
            val cursor = if (Build.VERSION.SDK_INT >= 30) resolver.query(collection, columns, Bundle().apply {
                putString(ContentResolver.QUERY_ARG_SQL_SELECTION, selection)
                putStringArray(ContentResolver.QUERY_ARG_SQL_SELECTION_ARGS, args)
                putInt(MediaStore.QUERY_ARG_MATCH_PENDING, MediaStore.MATCH_INCLUDE)
            }, null) else {
                @Suppress("DEPRECATION")
                resolver.query(MediaStore.setIncludePending(collection), columns, selection, args, null)
            }
            cursor?.use { rows ->
                while (rows.moveToNext()) resolver.delete(ContentUris.withAppendedId(collection, rows.getLong(0)), null, null)
            }
        }
    }
}
