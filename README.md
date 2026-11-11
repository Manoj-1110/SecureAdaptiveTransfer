# Secure Mobile Data Transfer with Adaptive AES-256

**SecureAdaptiveTransfer** is an Android 10+ application for real, encrypted phone-to-phone file sharing over Wi-Fi Direct or the same local Wi-Fi network. It selects a security profile from file metadata, network trust, battery/charging state and thermal conditions, and explains that decision.

Team: **Vaishanvi Amancharla, Nitya Tyagi, Manojkumar D**

The current app implements foreground transfers, explicit code confirmation on both devices, encrypted interrupted-transfer checkpoints, authenticated streaming, and verified Downloads publication. Automated verification and physical-phone verification are reported separately in [docs/VALIDATION.md](docs/VALIDATION.md). Two-phone radio and OEM background behavior remain subject to the [device checklist](docs/DEVICE_TEST_CHECKLIST.md).

## Architecture

| Component | Responsibility |
|---|---|
| `core/SecurityProfile.kt` | Three AES-256-GCM profiles and key-rotation policies |
| `core/ContextAnalyzer.kt` | Metadata sensitivity heuristic, context floors, thermal/battery rules and override guard |
| `core/CryptoPrimitives.kt` | JCA AES-GCM, SHA-256, HKDF-SHA256, PBKDF2-HMAC-SHA256 and P-256 ECDH |
| `core/SecureSession.kt` | SAT2 commitment/reveal handshake, SAS confirmation, authenticated framing and metadata |
| `core/TransferEngine.kt` | Streaming, authenticated resume negotiation, chunk/order/hash checks and batch receipts |
| `core/ResumeStore.kt` | Bounded, encrypted, durable verified-chunk journal |
| `app/MainActivity.kt` | Material UI, document/share selection, peer list, confirmation/password dialogs and lifecycle rendering |
| `app/MainViewModel.kt` | `UiState` and application-owned `TransferCoordinator`; owns sockets, real progress, prompts and cancellation |
| `app/TransferApplication.kt` | Owns the coordinator across Activity recreation and navigation |
| `app/TransferService.kt` | Android data-sync foreground service, notification progress/cancellation, power locks and timeout handling |
| `app/Telemetry.kt` | Network/device readings, SAF metadata, bounded staging and pending MediaStore downloads |
| `app/AndroidResumeStore.kt` | Wraps the local checkpoint key using a non-exportable Android Keystore AES key |
| `app/WifiDirectController.kt` | Runtime-safe discovery, peer selection, connection status and group lifecycle |

Paths in the table are relative to each module's `src/main/.../com/wmc/securetransfer/` package (`core` has an additional `core` package). `MainViewModel.kt` retains its original filename but now contains a coordinator owned by the application/service, rather than Activity-owned work.

Technologies: Kotlin 2.0.21, JDK 17, Gradle 8.14.3, Android Gradle Plugin 8.9.1, Android SDK 35, AndroidX, Material 3/ViewBinding, Kotlin coroutines/StateFlow, Java cryptography, TCP sockets, Wi-Fi P2P, Storage Access Framework, MediaStore and Android Keystore. No cloud service or internet relay carries files.

### Complete workflow

1. Select one or multiple documents, or share files into the app. Unknown-size providers are streamed into a bounded private staging file first.
2. Analyze metadata and context. An explicit security choice can raise the automatic requirement. Sensitive-file requirements cannot be lowered.
3. Start a foreground service and establish a TCP connection. Either Wi-Fi Direct group owner can host TCP, independently of which phone sends files.
4. Establish fresh ephemeral P-256 keys with the SAT2 handshake. Both screens show the six-digit short authentication string (SAS).
5. Both users compare all six digits and explicitly select **Codes match**. Either rejection aborts before file metadata/data acceptance. Unanswered prompts expire.
6. Hash the source using bounded memory. Send encrypted metadata binding filename, MIME, exact size, profile, per-session file ID, stable retry ID and SHA-256. Unlock Maximum files using the in-person shared password.
7. Authenticate any saved checkpoint, negotiate a verified prefix in the new encrypted session, and rehash that prefix on the sender before resuming. Encrypt and authenticate remaining chunks.
8. Verify chunk sequence, exact lengths, full SHA-256 and the encrypted file trailer. Keep all completed files pending until the entire advertised batch and authenticated completion summary match.
9. Publish verified files in Downloads/SecureTransfer. The receiver sends an encrypted batch receipt. The sender reports delivery only after verifying it.

## Adaptive security

| Profile | Chunk size | Data-key rotation | Additional protection |
|---|---|---|---|
| Standard | 1 MiB | Per session | AES-256-GCM, 128-bit authentication tags |
| Enhanced | 512 KiB | Per file | AES-256-GCM, file-specific HKDF key |
| Maximum | 256 KiB | Per chunk | AES-256-GCM; password-derived material mixed with ECDH-derived material |

All profiles use 256-bit AES. The profiles change chunking, key lifetime and password protection, not AES strength.

- Metadata sets a floor: ordinary audio/fonts/APKs and clearly public assets → Standard; photos, personal documents, archives and unknown types → Enhanced; passport/banking/medical/identity/credential indicators and private-key formats → Maximum.
- Trusted Wi-Fi Direct or known password-protected Wi-Fi → Standard network floor; cellular context → Enhanced; open/public/unknown Wi-Fi or unknown link → Maximum. Cellular is an assessment input, not a supported internet transport or relay.
- The stricter sensitivity/network floor applies. A user-marked public network is always treated as untrusted, including a Direct connection.
- Battery **20% or below while unplugged**, or severe thermal throttling, can relax **network-driven** Maximum to Enhanced. Sensitive files always remain Maximum. Charging removes battery-driven relaxation; thermal protection still applies.
- Size determines chunk counts and streaming; it does not override sensitivity.
- A manual profile can only raise the assessed profile. Choosing Standard for a personal document still uses Enhanced; choosing it for `passport_scan.pdf` still uses Maximum.

Filename/MIME classification is a heuristic and does not inspect or guarantee file contents. The UI states this explicitly. Select Maximum for sensitive contents that metadata cannot identify. Android 10–11 and some OEMs do not expose Wi-Fi security reliably; the conservative result may require Maximum on local Wi-Fi. Wi-Fi Direct remains available for trusted peer-to-peer transfers.

## Cryptographic protocol and storage

SAT2 is deliberately incompatible with the original SAT1 build. Install the same current APK on both phones.

- **Handshake:** both sides commit to SHA-256 of their public hello before revealing an ephemeral P-256 public key and random nonce. Each commitment is verified before deriving keys. This prevents choosing the final hello after seeing the other side's randomness to grind a desired SAS. Non-P-256, reflected, malformed and incompatible handshakes are rejected.
- **Key agreement:** P-256 ECDH; HKDF-SHA256 binds the ordered handshake transcript. Independent keys separate sender/receiver control traffic and file data. Secret keys and passwords are never sent or logged.
- **Peer authentication:** both users must compare the SAS over the nearby trusted visual/verbal channel and explicitly confirm. This is a six-digit human check with a finite guessing probability, not a certificate identity or a formally verified authenticated key-exchange protocol. Reject a mismatch and investigate repeated reconnects.
- **Nonces:** wire AES-GCM nonces use a 32-bit file/domain identifier plus a 64-bit chunk/control counter. File indices and order are checked; control directions and data keys are separated. Reconnecting generates fresh ECDH keys, file cryptographic IDs and password salts, so previous wire nonces are not reused under previous keys.
- **Maximum passwords:** 8–1024 characters; PBKDF2-HMAC-SHA256 with a fresh 128-bit salt and exactly **600,000 iterations**. The work factor is bounded to prevent attacker-selected KDF exhaustion. A password-derived key is mixed with ECDH-derived material using HKDF. Three receiver attempts are allowed. A strong shared passphrase remains necessary.
- **Authenticated metadata/order:** metadata is an encrypted control frame; chunk AAD binds file ID, index and last-chunk flag. Whole-file SHA-256 must match both the encrypted header and trailer. The batch-end summary binds advertised file count, total size and ordered metadata/hash transcript. The sender requires an encrypted matching receipt.
- **Downloads:** MediaStore entries remain `IS_PENDING=1` until file integrity and batch completion verify. Failed pending entries are deleted, orphaned pending entries are cleaned at startup, and a one-day expiration provides a system cleanup backstop. Filenames lose path components, control/bidirectional-format characters and unsafe characters. MediaStore creates new entries rather than overwriting an existing destination.
- **Resource limits:** at most 1,000 files, 64 GiB advertised per file and 128 GiB per batch; frames are capped near 1 MiB; metadata and KDF parameters have smaller bounds. The Android encrypted journal has an **8 GiB aggregate limit**, with a free-space reserve. Actual accepted transfers are constrained by that journal limit and available device storage; peak storage includes both encrypted staging and pending Downloads copies. Memory use is bounded by chunk buffers; completed output streams are closed while the batch awaits publication.

The implementation uses standard primitives but a project-specific wire protocol. The automated adversarial tests are useful evidence, not a substitute for an independent cryptographic audit.

### Interrupted-transfer recovery

The receiver stores only independently authenticated chunks in an app-private, encrypted journal under `noBackupFilesDir`. Its local 256-bit key is wrapped with Android Keystore; backup is disabled. Each stored record gets a fresh 256-bit derivation salt and independent AES-GCM key, binds the complete content identity and chunk index, and is synced before an atomic rename. No unauthenticated plaintext offset is trusted.

On a network interruption, unpublished MediaStore entries are removed but verified encrypted chunks are retained. Retry with **the same selected files while the sender app process remains alive**; its stable retry IDs survive rotation, app switching and reconnects. Start receiving again, confirm the new code on both phones and enter the shared password again. Both sides revalidate the saved prefix. The full source is hashed before transfer, so hashing can take time even when most network data is skipped.

Receiver checkpoints survive its process restart. If the wrapped local key is damaged or its Keystore alias is lost, unreadable receiver checkpoints are discarded with a visible log warning and fresh private storage is initialized. Sender selection/retry IDs are currently in application memory; a killed sender process must reselect and start a new transfer. Changing source content/profile invalidates an old checkpoint. Expired checkpoints are cleaned on startup/open; explicit receiver cancellation and **Delete saved partial transfers** remove its retained state. A sender cancellation appears to the receiver as a disconnect, so the receiver may retain its encrypted checkpoint until local deletion or expiry.

After success, checkpoints are discarded. If publication succeeds but the final receipt is lost, the sender cannot know whether delivery completed; a retry can create a second verified copy. MediaStore safely disambiguates destinations. Batch validation is complete before publication, but publishing several MediaStore entries is not an atomic multi-file transaction: a storage failure while publishing can leave already verified earlier entries visible and the remaining entries discarded.

### Background operation

The user starts a `dataSync` foreground service from the visible Activity. Its ongoing notification shows actual status/progress and provides cancellation. Activity recreation/Back/Home do not own the sockets. CPU/Wi-Fi locks support active transfers, and Android 15's data-sync timeout is handled by closing work and stopping the service. The service is not automatically restarted after process death; it does not bypass background execution restrictions.

Initial SAS/password prompts require returning to the app. A receiver waits up to two minutes for a connection; user prompts have two-minute limits and socket reads have three-minute inactivity limits. Background screen-lock behavior and OEM battery policies still need real-phone testing. Notifications may be denied on Android 13+; transfers can start, but normal notification controls are unavailable until permission is enabled.

## Build on this Mac / VS Code

A portable JDK 17, SDK 35, build tools, ADB and Android 15 test emulator were installed inside the ignored `.tools/` directory; Gradle dependencies are inside `.gradle-user-home/`. The global Java installation was not changed. `local.properties` points at the local SDK and is intentionally ignored.

From the project folder:

```sh
sh scripts/gradle-local.sh :core:test
sh scripts/gradle-local.sh :app:assembleDebug
sh scripts/gradle-local.sh :app:lintDebug
```

The helper detects the local tools, or respects existing `JAVA_HOME` and `ANDROID_HOME`. With a conventional JDK/SDK environment configured, the standard commands also work:

```sh
./gradlew :core:test
./gradlew :app:assembleDebug
./gradlew :app:lintDebug
```

The APK is **`app/build/outputs/apk/debug/app-debug.apk`**. Copy it to each phone and allow installation from the chosen file manager, or use USB debugging:

```sh
.tools/android-sdk/platform-tools/adb devices
.tools/android-sdk/platform-tools/adb -s PHONE_SERIAL install -r app/build/outputs/apk/debug/app-debug.apk
```

If copying the source to another computer, `.tools/` and caches are not included. Install JDK 17 and Android SDK platform/build-tools 35, set `JAVA_HOME`/`ANDROID_HOME`, and create `local.properties` with `sdk.dir=/absolute/path/to/sdk`. Gradle downloads dependencies on first use. A release build requires your own release signing setup; the demo APK is debug-signed.

## Send and receive

### Same local Wi-Fi

1. Connect both phones to the same Wi-Fi, with guest/client isolation disabled.
2. On B choose **Receive files → Start receiving** and note its Wi-Fi IPv4 address. Enter the numeric address on A without the interface label in parentheses.
3. On A select files. Review profiles and reasons; supply a shared password if Maximum is required. Tap **Encrypt & send**.
4. Compare and confirm all six digits on **both** phones. On B enter the Maximum password when asked.
5. Watch actual filename/progress/speed. B publishes verified files to **Downloads/SecureTransfer**, and A waits for B's receipt before showing success.

### Wi-Fi Direct

1. On both phones tap **Find nearby devices** and grant the requested Nearby devices/Location permission. Android 10–12 also needs the system Location switch enabled.
2. Select the peer and accept Android's prompt. Either phone may become group owner. The app automatically uses the owner's address and adjusts TCP direction; do not assume a fixed `192.168.49.1` address.
3. On B start receiving; on A select files and send. Confirm both codes and unlock Maximum files as above.

### Demonstration sequence

Send an ordinary audio file over Direct to show Standard, a photo to show Enhanced, and `passport_scan.pdf` to show Maximum. Explain the visible selection reasons and AES/key-rotation differences. Compare the two codes aloud and confirm both screens. Show B's exact received bytes/hash. Transfer a large file, rotate/press Home, show notification progress, interrupt the link, reconnect and retry the same selection to demonstrate authenticated recovery. Follow the complete [two-phone acceptance checklist](docs/DEVICE_TEST_CHECKLIST.md) before describing phone functionality as verified.

## Tests and troubleshooting

Run core tests and Android lint/build as above. With an emulator/phone connected:

```sh
sh scripts/gradle-local.sh :app:connectedDebugAndroidTest
```

Core tests use real loopback TCP and adversarial protocol peers, covering all profiles, empty/multi-chunk/multi-file transfers, matching keys, explicit confirmation rejection, bad passwords, tampering, truncation, reorder/replay, metadata/KDF/frame bounds, batch completion, adaptive floors, source mutation, encrypted recovery, corruption, cancellation, expiry, quotas and path sanitization. Android tests exercise the actual Keystore, MediaStore, Activity recreation, foreground notification/cancellation and application coordinator. Test listeners accepting a code automatically exist only inside automated test sources; production uses UI decisions.

Actual commands, pass/fail counts and report locations are in [docs/VALIDATION.md](docs/VALIDATION.md). The source audit is in [docs/AUDIT.md](docs/AUDIT.md).

| Symptom | Action |
|---|---|
| Java unavailable | Use the helper above, or install/configure JDK 17 and `JAVA_HOME` |
| SDK platform missing | Install `platforms;android-35` and `build-tools;35.0.0`; correct `local.properties` |
| Peers absent | Enable Wi-Fi, grant Nearby devices or precise Location, enable Location on Android 10–12, open both apps and retry discovery |
| Receiver unreachable | Start receiving again; verify the Wi-Fi interface IP, same network and absence of guest isolation/VPN routing interference |
| Codes missing/mismatched | Both apps must be the same SAT2 build. Reject mismatches; reconnect and compare again |
| Maximum unexpectedly selected | Unknown/open/public Wi-Fi is deliberately conservative; metadata is explained under each file |
| Password rejected | Check the shared passphrase exactly; after three attempts restart the transfer |
| Background confirmation appears stalled | Open the app from its notification and answer the code/password prompt within two minutes |
| Interrupted/slow resume | Keep the original sender selection, restart Receive, reconfirm the new code; source/prefix hashing still reads local data |
| Storage full | Free space and delete saved partial transfers; the journal limit is 8 GiB and publication temporarily needs a second copy |
| Old transfer no longer resumes | Check expiry, sender process restart, source/profile changes, cancellation or manual cleanup |
| Lint warnings | Inspect the report; dependency updates and conservative free-space checks are documented separately from errors |

Reference behavior: [Android Wi-Fi Direct](https://developer.android.com/develop/connectivity/wifi/wifip2p), [foreground-service timeouts](https://developer.android.com/develop/background-work/services/fgs/timeout), [MediaStore pending-item operations](https://developer.android.com/reference/android/provider/MediaStore#QUERY_ARG_MATCH_PENDING), and [OWASP PBKDF2 work-factor guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
