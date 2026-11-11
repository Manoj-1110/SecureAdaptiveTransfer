# Initial source audit — 11 November 2026

The supplied project consists of a JVM crypto/protocol module and an Android ViewBinding UI. No review slides, additional specifications, or AGENTS.md files were present in the workspace. The original team is Vaishanvi Amancharla, Nitya Tyagi, Manojkumar D.

Findings from source inspection:

- The six-digit code was displayed but never required confirmation. An active interceptor could establish two independent sessions and transfer before users compared codes.
- A manual profile override bypassed both sensitivity and context floors.
- Unknown Wi-Fi security and missing network capabilities were considered trusted.
- File counts, completion payloads, iteration upper bounds and several metadata fields were insufficiently validated. End-of-transfer could arrive before the advertised batch completed. The sender did not wait for an authenticated batch acknowledgement.
- Maximum-password caching was not wiped on exceptions; per-chunk key/plaintext cleanup also missed exceptional paths.
- Background operation depended on a ViewModel and keeping the display on. No foreground service existed.
- Interrupted files were deleted; no authenticated resume checkpoints existed.
- Wi-Fi Direct only automatically supplied the receiver address when the receiver won group-owner negotiation.
- MediaStore creation/open/commit failure paths could leave pending entries; the returned location omitted the actual filename.
- Cancellation did not reliably close the receive-side active socket or unblock all user prompts. Async context refresh could publish stale file assessments.
- The UI rebuilt every file row on every progress update, forced light mode and did not restore all stateful controls across recreation.

Environment: Apple Silicon macOS; no configured JDK, Gradle cache or Android SDK 35. An older SDK 33 extension platform and build tools 33.0.1 existed. Initial `./gradlew :core:test` was prevented by macOS quarantine; `sh ./gradlew :core:test` confirmed the missing Java runtime. A portable project-local JDK and SDK are being prepared; no historical test claim is treated as a current result.

Implementation and verification outcomes are recorded in README.md and docs/VALIDATION.md after the checks run.
