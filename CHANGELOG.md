## 0.7.0

### New RASP Check: Developer Mode Detection

* **New check:** `RaspShield.checkDeveloperMode()` detects whether Developer Options (Android) or Developer Mode (iOS 16+) is enabled on the device.
* **Android:** Reads `Settings.Global.DEVELOPMENT_SETTINGS_ENABLED` via `ContentResolver`. Returns `true` when Developer Options is turned on — the same check used by banking apps (Google Pay, PhonePe, Paytm) to detect elevated device privileges.
* **iOS 16+:** Uses filesystem and framework heuristics to detect when Developer Mode (Settings → Privacy & Security → Developer Mode) is enabled. Returns `false` on iOS < 16 where the toggle did not exist.
* **New Dart class:** `DeveloperModeDetector` in `lib/src/rasp/developer_mode_detector.dart`.
* **New native classes:** `DeveloperModeDetector.kt` (Android), `DeveloperModeDetector.swift` (iOS).
* **SecurityReport updated:** New `developerModeDetected` field (default `false`) — zero breaking changes for existing callers.
* **Included in `fullSecurityScan()`:** The 7th parallel check is now part of the full RASP scan.
* **Tests:** New test cases for individual check, full scan integration, and SecurityReport validation.

---

## 0.6.0

### New Module: Screen Shield — Anti-Screenshot & Screen Recording Prevention

* **New module:** `ScreenShield` prevents screenshots, screen recording, screen mirroring, and app-switcher thumbnails from capturing sensitive app content.
* **Android:** Uses `FLAG_SECURE` on the Activity window — the OS renders a black screen for all capture methods (screenshots, screen recording, Chromecast, MediaProjection, `adb screencap`, and app switcher thumbnails). Works on all Android versions (API 21+).
* **iOS:** Uses the secure `UITextField` layer trick — content rendered through the secure layer is blanked during capture. Screenshot detection via `userDidTakeScreenshotNotification`. Screen recording detection via `UIScreen.isCaptured`. App switcher guard via blur overlay on `willResignActive`.
* **New Dart classes:**
  * `ScreenShield` — Singleton with `enableProtection()`, `disableProtection()`, `enableAppSwitcherGuard()`, `disableAppSwitcherGuard()`, and detection streams.
  * `ScreenShieldConfig` — Immutable configuration with `copyWith()`.
  * `ScreenShieldScope` — Widget that enables protection on mount and disables on dispose (per-screen control).
  * `ScreenshotEvent` / `RecordingStateEvent` — Event models for detection callbacks.
  * `ScreenChannel` — Platform channel layer with graceful fallback on unsupported platforms.
* **New native classes:**
  * Android: `ScreenProtector.kt` (FLAG_SECURE), `ScreenRecordingDetector.kt` (virtual display heuristic).
  * iOS: `ScreenProtector.swift` (secure text field layer), `ScreenshotDetector.swift`, `ScreenRecordingDetector.swift` (`UIScreen.isCaptured`), `AppSwitcherGuard.swift` (blur overlay).
* **Plugin upgrade:** Android plugin now implements `ActivityAware` for Activity access. iOS plugin now implements `FlutterStreamHandler` for real-time event streaming via `EventChannel`.
* **Integration:** Added `screenConfig` parameter to `FlutterNeoShield.init()` and `FlutterNeoShield.screen` convenience getter. Zero breaking changes to existing APIs.
* **Tests:** 27 new tests (333 total, up from 306). New suites: `screen_shield_test`, `screen_channel_test`, `screen_shield_widget_test`.
* **Example:** New `ScreenShieldDemo` screen with interactive toggle controls, recording status indicator, and event log.

---

## 0.5.2

* Fixed an issue with `.pubignore` that incorrectly excluded `dio_shield_interceptor.dart`. This caused static analysis failures on pub.dev, which in turn prevented pub.dev from detecting support for all 6 platforms (iOS, Android, Web, Windows, macOS, Linux). The package now correctly reports full platform support.

## 0.5.1

### iOS Native Hardening
* **JailbreakDetector:** Added 20+ modern jailbreak paths (Sileo, Zebra, Substitute, checkra1n, Dopamine). Added URL scheme checks (sileo://, zbra://, filza://). Added symbolic link detection and sandbox write test.
* **FridaDetector:** Now checks ports 27042, 27043, and 4444. Fixed dangling pointer in socket code (undefined behavior). Added file-based Frida detection. Added connection timeout.
* **HookDetector:** Expanded from 4 to 20 suspicious library names (FridaGadget, SubstrateInserter, Liberty, Choicy, Shadow, etc.).

### Android Native Hardening
* **RootDetector:** Added 5 Magisk-specific paths and `Runtime.exec("which su")` check.
* **FridaDetector:** Added ports 27043, 4444. Added "frida-server" and "linjector" to memory maps scan.
* **HookDetector:** Expanded hook packages from 4 to 10 entries.
* **IntegrityDetector:** Fixed Lucky Patcher detection with proper `allowedInstallers` check.
* **EmulatorDetector:** Added QEMU chipname system property check.

### Test Coverage
* **306 tests** (up from 239 — 28% increase).
* New test suites: `rasp_shield_test`, `rasp_channel_test`, `dio_shield_interceptor_test`, `secure_paste_field_test`, `flutter_neo_shield_test`, `shield_report_test`, `pii_type_test`.
* Enhanced: `pii_detector_test` (SSN validation edge cases, API key false positives, name detection, international PII), `log_shield_test` (logJson, logError, timestamps, level filtering).

### Bug Fixes
* Fixed API key regex test that no longer matched after tightening regex to require digits.

---

## 0.5.0

### Security Hardening (47 issues fixed across all modules)

#### Breaking Changes
* **LogShield:** `sanitizeInDebug` now defaults to `true` (PII hidden in all modes). Set `sanitizeInDebug: false` to see raw values during development.
* **StringShield:** `enableCache` now defaults to `false` (opt-in). Cached plaintext secrets in memory were a security risk. Set `enableCache: true` if you need the performance.
* **LogShieldConfig:** `timestampFormat` replaced with `showTimestamp` (bool). ISO 8601 is always used when enabled.
* **PIIDetector:** Minimum name length for `registerName()` increased from 2 to 3 characters to reduce false positives.
* **ClipboardShield:** `cancelAutoClear()` is now `@visibleForTesting`. Use `clearNow()` instead.
* **MemoryShield:** `register()`/`unregister()` now accept `SecureDisposable` instead of `dynamic`.
* **Pubspec:** `source_gen`, `build`, and `analyzer` moved from `dependencies` to `dev_dependencies`. Consumers no longer pull in the analyzer toolchain.

#### RASP Shield
* **Fail-closed by default:** Platform errors now report threats as detected instead of silently passing. Controlled via `RaspChannel.failClosed`.
* **Parallel checks:** `fullSecurityScan()` runs all 6 checks in parallel to reduce TOCTOU window.
* **SecurityMode enforcement:** `fullSecurityScan()` now accepts `mode` parameter (`strict` throws `SecurityException`, `warn` logs, `custom` invokes callback).
* **Android fail-closed:** `checkHooks` and `checkIntegrity` return `true` (detected) when `applicationContext` is null.

#### Log Shield
* **Stack traces sanitized:** `shieldLogError()` now runs PII detection on stack traces in release mode.
* **Dead code removed:** `timestampFormat` config replaced with working `showTimestamp` boolean.

#### Memory Shield
* **Type-safe containers:** New `SecureDisposable` interface replaces `dynamic` in `MemoryShield`.
* **Wipe comparison bytes:** `SecureString.matches()` now zero-fills the comparison byte array after use.
* **Centralised channel:** `SecureString` and `SecureBytes` now use `MemoryShield.channel` instead of inline `MethodChannel` construction.
* **Security documentation:** Added Dart VM memory limitation warnings to `SecureString` and `SecureBytes` class docs.

#### Clipboard Shield
* **Improved paste detection:** Threshold raised from 2 to 3 chars; smarter divergence detection to reduce autocorrect false positives.
* **Overlay safety:** `SecureCopyButton` overlay removal now checks `mounted` before removing entries.
* **Reduced info disclosure:** Copy event logs no longer include the specific PII type.
* **Timer limitations documented:** `ClipboardShieldConfig.defaultExpiry` now documents clipboard history and app-kill limitations.

#### PII Detection Core
* **Expanded JSON sensitive keys:** 50+ keys now covered including `username`, `pwd`, `pin`, `session`, `cookie`, `iban`, `account_number`, `apiSecret`, and more.
* **International PII patterns:** Added IBAN, UK National Insurance Number, Canadian SIN, and passport number detection.
* **IPv6 detection:** IPv6 addresses are now detected alongside IPv4.
* **European date format:** Added DD/MM/YYYY pattern.
* **Tightened regexes:**
  * Bearer token requires 8+ token-like chars (reduces false positives on prose).
  * Phone number requires separators/prefix (reduces false positives on plain numbers).
  * SSN without dashes validates area/group/serial per SSA rules.
  * Email disallows consecutive dots per RFC 5322.
  * API key supports underscore prefix and 8+ char minimum.
* **Password field crash fix:** No longer throws `RangeError` when separator char is missing.
* **Duplicate pattern prevention:** `addPattern()` silently ignores duplicate type+regex combinations.
* **Efficient event queue:** `ShieldReport` uses `Queue` instead of `List.removeAt(0)`.

#### String Shield
* **Security documentation:** `ObfuscationStrategy` docs now clearly state all strategies are obfuscation, not encryption, with key/order stored in the binary.

#### Other
* **Init warning:** Debug assertion warns when modules are used before `FlutterNeoShield.init()`.
* **SecureValue safety:** `dispose()` wiper exceptions no longer prevent `unregister()`.

## 0.4.2

* Fixed missing `dio` dependency which caused issues with `DioShieldInterceptor` during downgrade analysis.
* Broadened dependency constraints to support the latest stable Dart SDK (`analyzer` and `build`).
* Documentation updates for perfect pub.dev score.

## 0.4.0

* **New Module:** RASP Shield (Runtime App Self Protection)
* Added Android & iOS native runtime security detections.
* Features include: `checkDebugger()`, `checkRoot()`, `checkEmulator()`, `checkFrida()`, `checkHooks()`, and `checkIntegrity()`.
* Call `RaspShield.fullSecurityScan()` to retrieve a full `SecurityReport`.
* Reorganized imports for modular access.

## 0.3.0

* Added full platform support for Web, macOS, Windows, and Linux.
* All features (Log Shield, Clipboard Shield, Memory Shield, String Shield) now work on all six Flutter platforms.
* Memory Shield uses native wipe on Android/iOS and Dart-side byte overwriting on other platforms.
* Added `flutter_web_plugins` SDK dependency for web plugin registration.
* No breaking changes — existing Android/iOS code is fully unaffected.

## 0.2.1

* Fixed pub.dev static analysis warnings.
* Broadened dependency constraints to support the latest analyzer and build versions.
* Shortened package description to meet pub.dev requirements.

## 0.2.0

* String Shield: compile-time string obfuscation with @Obfuscate() annotation
* Three obfuscation strategies: XOR, Enhanced XOR, Split-and-reassemble
* build_runner integration with code generation
* Runtime deobfuscation with optional caching and stats tracking
* Removed shieldPrint() (use shieldLog() instead)

## 0.1.0

* Initial release
* Core PII Detection Engine with 11 built-in patterns
* Log Shield: shieldLog(), JSON sanitizer, Dio interceptor
* Clipboard Shield: secureCopy() with auto-clear, SecureCopyButton, SecurePasteField
* Memory Shield: SecureString, SecureBytes, SecureValue with wipe-on-dispose
* Platform channels for native memory wipe (Android/iOS)
* Full example app with demos for all features
* 90%+ test coverage
