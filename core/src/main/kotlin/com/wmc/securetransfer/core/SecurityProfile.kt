package com.wmc.securetransfer.core

/** How often the AES-256 data key changes. */
enum class KeyRotation { PER_SESSION, PER_FILE, PER_CHUNK }

/**
 * The three adaptive security profiles from the design.
 * Every profile uses AES-256-GCM with 128-bit tags; they differ in
 * chunk size, key-rotation granularity and whether a password is mixed in.
 */
enum class SecurityProfile(
    val displayName: String,
    val chunkSize: Int,
    val rotation: KeyRotation,
    val requiresPassword: Boolean,
) {
    STANDARD("Standard", 1024 * 1024, KeyRotation.PER_SESSION, false),
    ENHANCED("Enhanced", 512 * 1024, KeyRotation.PER_FILE, false),
    MAXIMUM("Maximum", 256 * 1024, KeyRotation.PER_CHUNK, true);

    val chunkLabel: String
        get() = if (chunkSize >= 1024 * 1024) "${chunkSize / (1024 * 1024)} MB" else "${chunkSize / 1024} KB"

    val rotationLabel: String
        get() = when (rotation) {
            KeyRotation.PER_SESSION -> "Per session"
            KeyRotation.PER_FILE -> "Per file"
            KeyRotation.PER_CHUNK -> "Per chunk + password"
        }

    companion object {
        fun max(a: SecurityProfile, b: SecurityProfile) = if (a.ordinal >= b.ordinal) a else b
        fun fromId(id: Int): SecurityProfile =
            entries.getOrNull(id) ?: throw ProtocolException("Unknown security profile id $id")
    }
}
