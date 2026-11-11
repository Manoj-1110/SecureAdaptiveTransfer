# Two-phone acceptance checklist

Physical Wi-Fi Direct radios, OEM power management, Android system permission dialogs and two-phone local Wi-Fi have to be checked on real hardware. Emulator and JVM results do not establish that these checks passed.

Record phone models, Android versions, APK SHA-256, connection method, selected profile, source SHA-256, received SHA-256 and observed result for each run.

## Install and prepare

1. Install `app/build/outputs/apk/debug/app-debug.apk` on both Android 10+ phones. This is a demo debug build, not a production signing identity.
2. Allow notifications for background status. Allow Nearby devices on Android 13+ or precise Location on Android 10–12. On Android 10–12, turn on the Location system setting for discovery.
3. Keep phones unlocked for initial confirmation and password entry. Set distinctive phone names in Android Settings if discovery names are confusing.
4. Have a zero-byte file, a small audio file, a photo, `passport_scan.pdf`, an archive and a file of at least 100 MB available. Know their SHA-256 hashes using a trusted computer or file utility.

## Local Wi-Fi

1. Connect both phones to the same private Wi-Fi; guest/client isolation must be off.
2. On B, choose Receive files → Start receiving. Note the Wi-Fi address shown, without the interface suffix in parentheses. The listener waits two minutes.
3. On A, choose Send files, select files and enter B's numeric IP. Review each profile and reasons. Unknown Wi-Fi security deliberately uses conservative protection.
4. If Maximum is selected, enter an 8–1024 character shared password and tell B in person. Use a memorable multi-word passphrase for the demonstration.
5. Tap Encrypt & send. Read and compare all six digits on both phones. Tap Codes match on BOTH. No file should transfer before both confirmations.
6. On B enter the same password when asked. Verify progress, current filename, speed, completion and saved filenames in Downloads/SecureTransfer. Compare received hashes.
7. Repeat with A/B roles reversed.

## Wi-Fi Direct

1. On both phones tap Find nearby devices. Select the other phone on one device and accept Android's connection prompt.
2. Choose B as the receiver. Either phone may become group owner: the app adapts TCP client/server direction independently of file direction.
3. Start receiving on B; choose files and Encrypt & send on A. Confirm matching codes on both phones, unlock Maximum files, and compare received hashes.
4. Disconnect, form a new group with the opposite phone initiating, and repeat. Explicitly exercise both group-owner arrangements.
5. Repeat without an internet connection and with mobile data enabled, checking that Wi-Fi Direct is used and the app does not send through mobile data.

## Security and recovery

- Reject the code on either phone: neither phone should report success or publish a download.
- Leave one code unconfirmed: no transfer; eventually the connection is rejected/times out.
- Enter a wrong Maximum password three times: clean failure and no completed download.
- Try Standard override for `passport_scan.pdf`: it must remain Maximum, with its reason displayed.
- Mark the network public: ordinary files rise to Maximum. At low battery (20% or less, unplugged) or severe heat, only network-driven Maximum may relax to Enhanced; sensitive files remain Maximum. Avoid intentionally overheating hardware.
- Interrupt a transfer after several chunks by disabling/re-enabling Wi-Fi. On B start receiving again; on A retry with the SAME selected files while the sender app process is still alive. Confirm the NEW code on both phones and enter the password again. Check the resume log and exact final hash.
- Cancel on the receiver, and separately cancel via its notification: pending downloads and its saved checkpoints should disappear. Cancel on the sender: the receiver sees a disconnect and may keep encrypted checkpoints until receiver cancellation, manual deletion or expiry; no unauthenticated remote delete request is trusted.
- Use Delete saved partial transfers while idle; verify previously interrupted data no longer resumes.
- Change a source file between retries: the stale checkpoint must be rejected, not mixed with new bytes. Retry again to start cleanly.
- Retry after a lost final receipt: a duplicate verified download may be created; existing files must never be overwritten.

## Lifecycle and usability

- Rotate both phones while waiting, at code confirmation, at password entry and during transfer. Prompts must remain answerable and sockets must continue.
- Press Home/Back and lock the screen after confirming/unlocking. Verify foreground notification, real progress and final hashes when reopening. Initial confirmations require opening the app.
- Cancel using the foreground notification while the Activity is hidden. Reopen and retry.
- Exercise denied notification permission, denied Nearby devices/Location permission, Wi-Fi off, wrong IP, occupied port, guest-network isolation and peer disappearance. The app must give an error without claiming success.
- Check Android 10, Android 12, Android 13 and Android 15+ where hardware is available. Check both system light/dark modes and large font settings.
- If background work stops on a specific OEM, record model and battery settings; test with the vendor's documented unrestricted-battery option. Do not disable Android execution restrictions in code.

This checklist is pending until someone records actual phone results.
