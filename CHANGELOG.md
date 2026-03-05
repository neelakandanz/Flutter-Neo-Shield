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
