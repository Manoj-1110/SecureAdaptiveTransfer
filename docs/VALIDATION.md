# Verification and delivery record

Date: **11–12 November 2026, Asia/Kolkata**. Final delivery review: **12 November 2026**.

## Verified results

| Check | Actual result |
|---|---|
| Original untouched core suite | 7 tests passed before final implementation; preserved under `.tools/baseline/` |
| Current JVM CoreTests | 7 passed, 0 failed, 0 errors |
| Current JVM ProtocolTests | 31 passed, 0 failed, 0 errors |
| Android instrumentation | 9 passed, 0 failed, 0 errors on Android 15 / API 35 AOSP ARM64 emulator |
| `:app:assembleDebug` | Passed; final APK exists |
| `:app:lintDebug` | Passed; 0 errors, 13 warnings |
| APK signature | `apksigner verify --verbose` passed; APK Signature Scheme v2, Android Debug certificate |
| Final APK installation | `adb -s emulator-5554 install -r ...` returned Success |
| Final launch | `am start -W` returned Status: ok |
| Light/dark UI | Actual emulator screenshots captured and visually reviewed |
| Physical phones / Wi-Fi Direct radios | Not tested; hardware acceptance remains pending |

The current automated total is **47 passing tests: 38 JVM + 9 Android**. The baseline seven are a subset/history, not seven additional current tests. The follow-up check reran all 38 core tests using `:core:cleanTest :core:test`; all passed afresh.

Final combined command:

```sh
sh scripts/gradle-local.sh :core:test :app:assembleDebug :app:lintDebug :app:connectedDebugAndroidTest --console=plain
```

It completed with `BUILD SUCCESSFUL`. The standard `:core:test` and `:app:assembleDebug` tasks are run through the helper using the project-local JDK/SDK and Gradle cache. Initial missing Java/SDK and macOS launcher quarantine were resolved locally.

## Delivered APK

- File: `app/build/outputs/apk/debug/app-debug.apk`
- Size: **12,307,279 bytes**
- Application ID: `com.wmc.securetransfer`
- Version: `2.0`, version code `2`
- Minimum SDK: `29` (Android 10); target/compile SDK: `35`
- Debug-signed for installation and demonstrations. Release signing remains your own configuration.
- SHA-256: `7977cb0d722cb04b3d78adb0c92afd8cd251fed9112c43df9b548d222a8afd56`

`aapt dump badging` verified the packaged application/version/SDK values. The hash identifies this delivered APK; rebuilding can produce a different hash.

## What Android tests exercised

- `orphanedPendingDownloadsAreRemovedOnStartupCleanup`
- `androidKeystoreResumesEncryptedCheckpointAcrossStoreInstances`
- `loopbackEncryptedBatchIsPublishedWithExactBytesForAllProfiles`
- `foregroundReceiverSurvivesRecreationAndBackgroundAndCancels`
- `coordinatorPromptsForCodeAfterRecreationAndReceivesRealFile`
- `homeAndReceiveModeSurviveActivityRecreation`
- `mediaStoreKeepsPendingFilesHiddenAndAbortDeletesThem`
- `switchingFileDirectionRetainsNegotiatedGroupOwnerAddress`
- `senderUiTransfersSelectedDocumentAndRejectsInvalidAddress`

The tests use actual Android Keystore and MediaStore, TCP sockets, the foreground service, notification cancellation PendingIntent, Activity recreation and the real application coordinator. The code-confirmation test compares the peer code, recreates the Activity while its decision is pending, clicks the actual Codes match dialog, confirms the test peer separately, and checks exact downloaded bytes. Test peers accept codes only in test sources; production prompts both users.

The group-owner address test injects platform connection facts to exercise UI/coordinator state transitions; it does **not** prove Wi-Fi Direct discovery, group negotiation or radio routing on hardware. Foreground testing covers Activity recreation and backgrounding on the emulator, not every OEM or a long physical screen-lock session.

## Failures found and resolved

- Original code did not enforce peer-code confirmation; SAT2 now fails closed and requires explicit decisions from both endpoints.
- Manual profile choices could downgrade sensitive files; assessment floors now apply in the UI, sender and sensitive-metadata validation.
- Early/malformed batch completion, loose metadata counts and unbounded password work parameters were hardened and tested.
- Added commit/reveal handshakes, fresh-session authenticated recovery, encrypted checkpoint integrity, bounded framing and source-change rejection.
- Fixed password/key cleanup, pending-download creation/publication failures, and closed completed output streams before batch publication.
- The first emulator run exposed the default exclusion of pending MediaStore rows. Startup cleanup now explicitly includes pending rows, with an Android 10 fallback and a regression test.
- Emulator testing exposed concurrent Keystore initialization replacing an alias. Initialization is serialized; unauthenticatable local state is discarded with a visible warning rather than reused.
- Espresso initially stalled on active animation timing. Android instrumentation disables window animations, and animator scale was disabled only in the disposable test emulator.
- Fixed precise/coarse location permissions, notification/service declarations, reverse TCP routing for either group owner, and retaining owner addresses when switching file direction.
- Visual review exposed light status-bar contrast and stale controller callbacks after rotation; both were corrected and the lifecycle assertion passes.
- A transient compiler error from conflicting `ProtocolException` imports was fixed. No known build/test blockers remain.

## Remaining warnings

Lint is enabled; no error baseline or broad suppression was added. Its 13 warnings are:
- 10 `GradleDependency` notices: newer releases exist. Existing API-35-compatible dependencies are pinned; upgrading the toolchain/dependencies is a separate compatibility change.
- 2 `UsableSpace` suggestions: current checks reserve actual free space rather than reclaiming other applications’ caches via `StorageManager`.
- 1 `ButtonStyle` suggestion for the file-picker action row.

Gradle also reports an AGP lint-model attribute lookup deprecation under `--warning-mode all`. This toolchain builds under the pinned Gradle 8.14.3; it must be reviewed before upgrading to Gradle 9/10. An early portable compiler-daemon startup retry recovered and all affected checks later passed. A host `shasum` invocation failed due to the host locale; the delivered SHA-256 above was calculated successfully with Python hashlib instead.

## Reports and screenshots

- [Core test report](../core/build/reports/tests/test/index.html)
- [Android runtime test report](../app/build/reports/androidTests/connected/debug/index.html)
- [Lint report](../app/build/reports/lint-results-debug.html)
- [Light-mode screenshot](screenshots/home-light.png)
- [Dark-mode screenshot](screenshots/home-dark.png)

Reports in build directories are generated artifacts and are replaced on subsequent builds. The screenshots are actual captures of the final installed APK.

## Remaining acceptance work and operating limits

1. Install this APK on two real Android 10+ phones and complete [DEVICE_TEST_CHECKLIST.md](DEVICE_TEST_CHECKLIST.md). Record device models, OS versions, connection method, matching SHA-256 hashes, cancellation/recovery and background results. No physical-device installation or transfer success is claimed.
2. Verify Wi-Fi Direct discovery/negotiation, both group-owner arrangements, two-phone local Wi-Fi routing, API 29–34/36+ behavior and OEM screen-lock policies. Only API 35 runtime behavior was exercised here.
3. Resume requires the original sender selection and a live sender app process. Receiver checkpoints survive process restart; sender selection/IDs currently do not. After a killed sender process, reselect files and restart. Checkpoints expire after one day and can be manually deleted.
4. Encrypted checkpoint storage is capped at 8 GiB aggregate and publication needs additional device space. Free space or use smaller batches; unknown-size selected files may also need private staging space.
5. A lost final receipt can produce a duplicate verified download on retry. MediaStore publication is per file, so a publication failure can leave already verified earlier files visible. Existing destinations are never overwritten by this implementation.
6. Initial code/password confirmation needs the app visible. Long-running Android 15 timeout behavior is implemented but the six-hour allowance was not exhausted in tests. Severe thermal hardware behavior and OEM restrictions remain phone checks.
7. The protocol uses standard primitives but is project-specific; this review/test suite is not independent cryptographic certification. Metadata sensitivity detection remains a heuristic.

## Source files changed

| Status | Path |
|---|---|
| Updated | `core/src/main/kotlin/com/wmc/securetransfer/core/ContextAnalyzer.kt` |
| Updated | `core/src/main/kotlin/com/wmc/securetransfer/core/CryptoPrimitives.kt` |
| Added | `core/src/main/kotlin/com/wmc/securetransfer/core/ResumeStore.kt` |
| Updated | `core/src/main/kotlin/com/wmc/securetransfer/core/SecureSession.kt` |
| Updated | `core/src/main/kotlin/com/wmc/securetransfer/core/TransferEngine.kt` |
| Updated | `core/src/test/kotlin/com/wmc/securetransfer/core/CoreTests.kt` |
| Added | `core/src/test/kotlin/com/wmc/securetransfer/core/ProtocolTests.kt` |
| Updated | `app/build.gradle.kts` |
| Added | `app/src/androidTest/java/com/wmc/securetransfer/AndroidIntegrationTests.kt` |
| Updated | `app/src/main/AndroidManifest.xml` |
| Added | `app/src/main/java/com/wmc/securetransfer/AndroidResumeStore.kt` |
| Updated | `app/src/main/java/com/wmc/securetransfer/MainActivity.kt` |
| Updated | `app/src/main/java/com/wmc/securetransfer/MainViewModel.kt` |
| Updated | `app/src/main/java/com/wmc/securetransfer/Telemetry.kt` |
| Added | `app/src/main/java/com/wmc/securetransfer/TransferApplication.kt` |
| Added | `app/src/main/java/com/wmc/securetransfer/TransferService.kt` |
| Updated | `app/src/main/java/com/wmc/securetransfer/WifiDirectController.kt` |
| Added | `app/src/main/res/drawable/ic_notification.xml` |
| Updated | `app/src/main/res/layout/activity_main.xml` |
| Updated | `app/src/main/res/values/strings.xml` |
| Updated | `app/src/main/res/values/themes.xml` |
| Added | `app/src/main/res/values-night/colors.xml` |

Also updated/added: `.gitignore`, `README.md`, `scripts/gradle-local.sh`, `docs/AUDIT.md`, this record, `docs/DEVICE_TEST_CHECKLIST.md`, and the screenshots. Generated ignored environment/artifacts include `local.properties`, `.tools/`, `.gradle-user-home/`, module build outputs and the APK. The original launcher quarantine attribute was removed after inspection; launcher source was preserved. Original academic identity and team information remain in README.md.

## Follow-up check — 12 November 2026

At the user's request, the core tests were executed afresh, the build and lint were checked again, and the Android suite was expanded to cover the application sender. All **38 core tests and 9 Android tests passed**, with zero failures/errors. Lint remains at 0 errors / 13 warnings. APK signature verification passed and the delivered APK checksum is unchanged.

The added sender test reads a real MediaStore document, rejects an invalid destination without starting a transfer, obtains explicit confirmation through the actual code dialog, sends 4,200,003 bytes through the application coordinator and checks exact received bytes and successful status. It initially failed because its test listener bound the platform-default loopback address while the sender used IPv4. Binding both ends to 127.0.0.1 fixed the test setup; the complete suite then passed. No production app code was changed during this follow-up.

Commands actually executed:

```sh
sh scripts/gradle-local.sh :core:cleanTest :core:test :app:assembleDebug :app:lintDebug --console=plain
sh scripts/gradle-local.sh :app:connectedDebugAndroidTest :app:lintDebug --console=plain
JAVA_HOME="$PWD/.tools/java17" sh .tools/android-sdk/build-tools/35.0.0/apksigner verify --verbose app/build/outputs/apk/debug/app-debug.apk
```

Only the local emulator was connected. Physical phone/network/OEM checks remain pending as described above. Passing these tests does not establish that every phone, file provider, file size, permission setting or network condition is error-free.
