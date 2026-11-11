package com.wmc.securetransfer.core

import java.util.Locale

enum class Sensitivity { LOW, PERSONAL, SENSITIVE }

enum class NetworkRisk(val label: String) {
    TRUSTED("Trusted Wi-Fi / Wi-Fi Direct"),
    CELLULAR("Cellular"),
    UNTRUSTED("Public / untrusted Wi-Fi"),
}

/** Facts about one file, gathered from metadata only (never file contents). */
data class FileFacts(val name: String, val mimeType: String?, val sizeBytes: Long)

/** Device telemetry collected by the platform layer. */
data class DeviceContext(
    val networkRisk: NetworkRisk,
    val batteryPercent: Int,
    val isCharging: Boolean,
    val thermalStressed: Boolean,
) {
    val resourceStressed: Boolean
        get() = thermalStressed || (!isCharging && batteryPercent in 0..LOW_BATTERY_PERCENT)

    companion object { const val LOW_BATTERY_PERCENT = 20 }
}

data class Assessment(
    val file: FileFacts,
    val sensitivity: Sensitivity,
    val profile: SecurityProfile,
    val reasons: List<String>,
) {
    /** A manual choice can raise security, but cannot weaken the assessed requirement. */
    fun withOverride(requested: SecurityProfile?): SecurityProfile =
        requested?.let { SecurityProfile.max(profile, it) } ?: profile
}

/**
 * Telemetry engine: scores sensitivity, size, network and battery and picks a profile.
 *
 * Rules
 *  1. Sensitivity sets a floor: LOW→Standard, PERSONAL→Enhanced, SENSITIVE→Maximum.
 *  2. Network sets a floor:     trusted→Standard, cellular→Enhanced, public→Maximum.
 *  3. The stronger floor wins.
 *  4. If the device is resource-stressed (low battery and not charging, or thermal
 *     throttling) and Maximum was chosen only because of the network, it relaxes to
 *     Enhanced. Sensitive data is never relaxed.
 */
object ContextAnalyzer {

    const val LARGE_FILE_BYTES = 512L * 1024 * 1024

    private val sensitiveKeywords = listOf(
        "passport", "aadhaar", "aadhar", "pan_card", "pancard", "pan card", "bank", "statement",
        "salary", "payslip", "pay_slip", "itr", "tax", "medical", "health", "prescription",
        "password", "credential", "secret", "confidential", "private", "ssn", "license", "licence",
        "otp", "pin", "account", "kyc", "visa",
    )

    private val sensitiveExtensions = setOf(
        "key", "pem", "p12", "pfx", "kdbx", "keystore", "jks", "ovpn", "env", "gpg", "asc", "wallet",
    )

    private val lowRiskKeywords = listOf("wallpaper", "meme", "sticker", "public", "brochure", "poster")

    fun classify(file: FileFacts): Sensitivity {
        val name = file.name.lowercase(Locale.ROOT)
        val ext = name.substringAfterLast('.', "")
        val mime = (file.mimeType ?: "").lowercase(Locale.ROOT)
        val tokens = name.split(Regex("[^a-z0-9]+")).filter { it.isNotEmpty() }.toSet()

        val keywordHit = sensitiveKeywords.any { kw ->
            if (kw.length <= 3) kw in tokens else name.contains(kw)
        }
        if (keywordHit || ext in sensitiveExtensions ||
            mime.contains("pkcs") || mime.contains("x509") || mime.contains("pgp")
        ) return Sensitivity.SENSITIVE

        if (mime.startsWith("audio/") || mime.startsWith("font/") ||
            mime == "application/vnd.android.package-archive" || ext == "apk" ||
            lowRiskKeywords.any { name.contains(it) }
        ) return Sensitivity.LOW

        // Photos, videos, documents, contacts, archives and unknown types are treated as personal.
        return Sensitivity.PERSONAL
    }

    fun assess(file: FileFacts, ctx: DeviceContext): Assessment {
        require(file.sizeBytes in 0..TransferLimits.MAX_FILE_BYTES) { "Unsupported file size" }
        val reasons = mutableListOf<String>()
        val sensitivity = classify(file)

        val sensFloor = when (sensitivity) {
            Sensitivity.LOW -> SecurityProfile.STANDARD
            Sensitivity.PERSONAL -> SecurityProfile.ENHANCED
            Sensitivity.SENSITIVE -> SecurityProfile.MAXIMUM
        }
        reasons += "Data sensitivity: ${sensitivity.name.lowercase()} → at least ${sensFloor.displayName}"

        val netFloor = when (ctx.networkRisk) {
            NetworkRisk.TRUSTED -> SecurityProfile.STANDARD
            NetworkRisk.CELLULAR -> SecurityProfile.ENHANCED
            NetworkRisk.UNTRUSTED -> SecurityProfile.MAXIMUM
        }
        reasons += "Network: ${ctx.networkRisk.label} → at least ${netFloor.displayName}"

        var profile = SecurityProfile.max(sensFloor, netFloor)

        if (ctx.resourceStressed) {
            val why = if (ctx.thermalStressed) "device is thermally throttled"
            else "battery at ${ctx.batteryPercent}% and not charging"
            if (profile == SecurityProfile.MAXIMUM && sensitivity != Sensitivity.SENSITIVE) {
                profile = SecurityProfile.ENHANCED
                reasons += "Resources: $why → relaxed to Enhanced (still AES-256-GCM, per-file keys)"
            } else {
                reasons += "Resources: $why → no relaxation (data or network requires ${profile.displayName})"
            }
        } else {
            reasons += "Resources: battery ${ctx.batteryPercent}%${if (ctx.isCharging) " (charging)" else ""}, no throttling"
        }

        val chunks = maxOf(1L, file.sizeBytes / profile.chunkSize + if (file.sizeBytes % profile.chunkSize > 0) 1 else 0)
        reasons += "Size: ${formatBytes(file.sizeBytes)} → $chunks chunk(s) of ${profile.chunkLabel}" +
            if (file.sizeBytes >= LARGE_FILE_BYTES) " (large file, streamed)" else ""

        return Assessment(file, sensitivity, profile, reasons)
    }

    fun formatBytes(b: Long): String = when {
        b < 1024 -> "$b B"
        b < 1024L * 1024 -> String.format(Locale.US, "%.1f KB", b / 1024.0)
        b < 1024L * 1024 * 1024 -> String.format(Locale.US, "%.1f MB", b / (1024.0 * 1024))
        else -> String.format(Locale.US, "%.2f GB", b / (1024.0 * 1024 * 1024))
    }
}
