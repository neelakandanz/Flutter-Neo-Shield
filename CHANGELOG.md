## 2.1.1

### Location Shield — Enhanced Spoofing Detection
- Added `checkDefaultMockLocationApp` to `SpoofingAppDetector` on Android to detect the system-level mock location app setting.
- Resolved Android build errors and incremental compilation issues related to the detector implementation.
- Updated CLI Security Scanner version in reports to match the package version.

## 2.1.0

### CLI Security Scanner — Advanced Deep Analysis

New `dart run flutter_neo_shield:scan` command-line tool that performs **90+ security checks** across **11 categories** with **5 output formats**. Zero changes to existing shields — 100% new code in separate files.

#### Scanner Engine

- **Pure Dart CLI** — runs without Flutter SDK, no Flutter imports
- **File traversal engine** — recursively scans project files, skips build/cache/generated directories
- **Pattern-based + custom rules** — regex content matching with exclusion patterns, plus custom check functions for config parsing and file-existence rules
- **Parallel-safe** — rules are stateless, engine is single-pass
- **Performance** — skips files >1MB, only scans relevant file extensions, deduplicates false positives

#### 11 Detection Categories (90+ Rules)

##### 1. Hardcoded Secrets (12 rules)
- API keys: `sk_live_`, `pk_test_`, `AKIA`, `AIza`, `ghp_`, `glpat-`, `xox[bpas]-`
- OAuth/Bearer tokens, JWT tokens (`eyJ...`)
- Private keys (PEM-encoded RSA/EC/DSA)
- Database connection strings (mongodb://, postgres://, mysql://, redis://)
- Firebase credentials, cloud provider keys (AWS, GCP, Azure)
- Webhook URLs (Slack, Discord, Stripe)
- Hardcoded encryption keys/IVs, passwords/PINs
- SSH private key references, CI/CD tokens

##### 2. Insecure Network Configuration (9 rules)
- HTTP URLs (non-HTTPS, excluding localhost)
- Disabled certificate validation (`badCertificateCallback => true`)
- HttpClient without certificate pinning
- Android `usesCleartextTraffic="true"`
- Trust-all network security config
- Unencrypted WebSocket (`ws://`)
- SSL/TLS verification bypass
- CORS wildcard origin, unconditional proxy trust

##### 3. Insecure Data Storage (9 rules)
- Tokens/passwords in SharedPreferences
- Unencrypted SQLite (sqflite without sqlcipher)
- Secrets written to plain files
- Hive/GetStorage/MMKV without encryption
- Web localStorage/sessionStorage for sensitive data
- Sensitive data in cache/temp directories
- Sensitive data in print/log statements
- Secrets bundled in assets/ (.env, credentials.json, .pem, .key)

##### 4. Platform Configuration Weaknesses (10 rules)
- `android:debuggable="true"` in release
- Exported Android components without permissions
- `android:allowBackup="true"`
- iOS `NSAllowsArbitraryLoads` ATS exception
- Custom URL schemes without validation
- Missing ProGuard/R8 for release builds
- Missing `--obfuscate --split-debug-info` in CI/CD
- minSdkVersion below 23
- Over-requested dangerous permissions

##### 5. Authentication & Session Flaws (7 rules)
- `local_auth` biometric without cryptographic binding
- Token in URL query parameters
- Token stored without expiry check
- Deep link parameters used without validation
- User input concatenated into API calls
- Hardcoded test/user credentials
- Auto-login without device binding

##### 6. Cryptography Weaknesses (8 rules)
- MD5/SHA1 for security purposes
- AES ECB mode
- Static/hardcoded IV or nonce
- Password used directly as encryption key
- Insufficient key length (AES-128, RSA-1024)
- `Random()` instead of `Random.secure()` for security
- Custom cryptographic implementations
- Predictable random seeds

##### 7. Code Quality & Injection (8 rules)
- SQL injection (string interpolation in rawQuery)
- XSS via WebView `evaluateJavascript()` with unsanitized input
- Command injection via `Process.run()` with user input
- Path traversal (`../`) in file operations
- Unvalidated JSON deserialization
- ReDoS (catastrophic regex backtracking)
- `dart:mirrors` / dynamic code execution
- Unsafe HTML rendering with user content

##### 8. Dependency & Supply Chain (7 rules)
- Missing pubspec.lock
- Unpinned dependency versions (`^`, `any`, `>=`)
- Dependency confusion risk (private package names)
- pubspec.lock in .gitignore
- Plugins with native code from unknown sources
- Git dependencies without commit hash pin
- `dependency_overrides` present

##### 9. Privacy & Compliance (7 rules)
- PII patterns in print/log statements
- User data in exception messages
- Cached data without cleanup/TTL
- Analytics initialized without consent check
- Device identifier collection without disclosure
- `Clipboard.setData` without auto-clear
- Sensitive screens without screenshot protection

##### 10. Build & Release Security (6 rules)
- Web source maps in build output
- .env files in project root (not gitignored)
- Keystore passwords hardcoded in build.gradle
- Test packages imported in lib/ code
- Dev-only packages imported in lib/

##### 11. Flutter/Dart Specific (7 rules)
- MethodChannel without input validation
- AppLifecycleState handler without screen protection
- WebView JavascriptChannel without origin check
- Global mutable variables holding sensitive data
- Missing `mounted` check after await in StatefulWidget
- Deep link routes without auth guards
- WebView with JavaScript + file access enabled

#### 5 Output Formats

- **ASCII** — Color-coded terminal report with severity bars, score card, letter grade (A-F)
- **JSON** — Machine-readable structured output for custom tooling
- **SARIF 2.1.0** — GitHub Advanced Security compatible format
- **HTML** — Dark-themed shareable audit report with tables and badges
- **JUnit XML** — CI pipeline test-result format (Jenkins, GitLab CI, Azure DevOps)

#### Scanner Modes

- `--quick` — Secrets + network only (21 rules, fast CI gate)
- `--standard` — All categories except dependency/privacy/build (73 rules, default)
- `--deep` — All 90+ rules including dependency audit and compliance checks
- `--ci` — Non-zero exit code on critical/high findings
- `--exclude` — Skip file patterns
- `--exclude-rules` — Skip specific rule IDs
- `--min-severity` — Filter by minimum severity level
- `--list-rules` — Print all available rules and exit

#### Security Score

- **0-100 score** with letter grade (A-F)
- Score penalizes by severity weight: critical (5), high (4), medium (3), low (2), info (1)
- `--ci` mode: exits with code 1 if any critical or high severity findings

#### Architecture

- **Zero existing code changes** — all new files in `lib/src/cli_scanner/` and `bin/scan.dart`
- **Pure Dart** — no Flutter dependency in scanner code, runs as `dart run`
- **Modular rules** — each category in its own file, registered via `RuleRegistry`
- **Extensible** — add custom rules by creating new rule files and registering them
- **Version:** 2.0.0 → 2.1.0

---

## 2.0.0

### 20 New Security Shields — The Biggest Update Ever

Major release adding **13 new shield modules** and **7 security enhancements** to existing shields. Every feature is implemented in separate files — zero changes to existing APIs. Full backward compatibility.

#### New Shield Modules

##### 1. Overlay/Tapjacking Shield
- **Android:** Detects `TYPE_APPLICATION_OVERLAY` windows drawn over your app, `filterTouchesWhenObscured` enforcement
- **iOS:** OS-level overlay prevention (check for unexpected windows)
- **Web:** Clickjacking detection via iframe embedding checks
- API: `OverlayShield.instance.enableTouchFiltering()`, `checkOverlayAttack()`, `checkClickjacking()`
- New files: `lib/src/overlay_shield/`, Android `OverlayDetector.kt`, iOS `OverlayDetector.swift`, all desktop platforms

##### 2. Accessibility Service Abuse Detection
- **Android:** Scans `AccessibilityManager.getEnabledAccessibilityServiceList()` for non-system services that can read screen content and capture keystrokes
- **iOS:** Detects VoiceOver, SwitchControl, AssistiveTouch status
- **macOS:** Checks `AXIsProcessTrusted()` for accessibility trust
- **Windows:** `SystemParametersInfo(SPI_GETSCREENREADER)` detection
- **Linux:** AT-SPI bus detection
- API: `AccessibilityShield.checkAccessibilityAbuse()`, `getEnabledServices()`, `isScreenReaderActive()`

##### 3. Secure Input Shield (Anti-Keylogger)
- **Android:** Detects third-party keyboards via `InputMethodManager`, identifies non-system IME (Samsung, Huawei, MIUI, OPPO, OnePlus, LGE system keyboards whitelisted)
- **iOS:** Detects non-Apple keyboard extensions via `UITextInputMode`
- **macOS:** Carbon `TISCreateInputSourceList` inspection
- **Flutter widget:** `SecureTextField` — forces system keyboard, disables IME personalized learning, suggestions, and autocorrect
- API: `SecureInputShield.isThirdPartyKeyboardActive()`, `getCurrentKeyboardPackage()`, `isKeyloggerDetected()`

##### 4. Certificate Pinning Shield
- Pin hosts to SHA-256 certificate hashes: `CertPinShield.instance.pin('api.example.com', hashes)`
- Creates `HttpClient` with pinned certificates via `badCertificateCallback`
- `validateCertificate(host, hash)` for manual validation
- Supports pin rotation with multiple backup hashes

##### 5. WebView Shield
- URL validation: blocks `javascript:`, `file://`, enforces HTTPS
- Host allowlisting: `configure(allowedHosts: {'api.example.com'})`
- `recommendedSettings` map for hardened WebView configuration
- `validateUrl()` returns null (safe) or error message (blocked)

##### 6. Secure Storage Shield (Keystore/Keychain)
- **Android:** AES-256-GCM encrypted SharedPreferences with app-generated key
- **iOS/macOS:** Keychain Services with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
- **Windows:** DPAPI-backed encryption (placeholder)
- **Linux:** App-level encrypted storage (placeholder)
- **Web:** In-memory fallback
- API: `SecureStorageShield.instance.write(key, value)`, `.read(key)`, `.delete(key)`, `.wipeAll()`

##### 7. Biometric Auth Shield
- **iOS:** `LAContext` with Face ID/Touch ID/Optic ID support, device credential fallback
- **Android:** Biometric prompt support (placeholder — use with `BiometricShield.instance.authenticate()`)
- `checkAvailability()` returns `BiometricAvailability` with supported types
- `authenticate(reason:)` returns `BiometricResult` with success/error

##### 8. Data-at-Rest Encryption Shield
- AES-256 key generation via `Random.secure()`
- XOR-with-IV encryption for lightweight local data protection
- `encryptString()` / `decryptString()` with base64 encoding
- `encryptJson()` / `decryptJson()` for structured data
- Combine with SecureStorageShield for key management

##### 9. Continuous RASP Monitor
- Background watchdog: `RaspMonitor.instance.startMonitoring(interval: Duration(seconds: 30))`
- `Stream<SecurityReport>` via `reports` for real-time threat notifications
- Threat counter: `threatCount` tracks cumulative detections
- Graduated response modes: silent, warn, strict, custom
- `stopMonitoring()` to stop the periodic scan

##### 10. Threat Response Engine
- Automated incident response: `ThreatResponse.instance.respond(report, config)`
- `wipeSecrets()` — clears all MemoryShield containers
- `wipeStorage()` — clears all SecureStorageShield data
- `wipeAll()` — memory + storage wipe
- `ThreatResponseConfig` — configure wipe-on-threat, kill-on-critical (3+ simultaneous threats)
- Listener pattern: `addListener((report) => handleThreat(report))`

##### 11. Device Binding Shield
- **Android:** SHA-256 of ANDROID_ID + Build.FINGERPRINT + hardware properties
- **iOS:** SHA-256 of identifierForVendor + device model + hw.machine
- **macOS:** IOPlatformUUID + hw.model hash
- **Windows:** MachineGuid from registry + ComputerName hash (SHA-256 via CryptoAPI)
- **Linux:** /etc/machine-id + hostname hash
- API: `DeviceBindingShield.instance.getDeviceFingerprint()`, `validateBinding(expectedFingerprint)`

##### 12. DNS Shield
- Pin domains to expected IPs: `DnsShield.instance.pinDomain('api.example.com', {'1.2.3.4'})`
- `validateDns(domain)` resolves and compares against pinned IPs
- `validateAll()` checks all pinned domains, returns failure map
- Detect DNS spoofing / manipulation

##### 13. TLS Configuration Shield
- `createSecureClient()` — HttpClient with hardened TLS defaults
- `validateHost(host)` — connect and verify TLS negotiation
- `validateHosts(hosts)` — batch validation, returns failure map

#### Security Enhancements

##### 14. Permission Shield
- **Android:** Camera/Microphone in-use detection, background location monitoring
- **iOS:** AVCaptureDevice authorization status monitoring
- API: `PermissionShield.isCameraInUse()`, `isMicrophoneInUse()`, `isLocationAccessedInBackground()`

##### 15. Data Leak Prevention (DLP) Shield
- `sanitizeDeepLink(url)` — strips PII from deep link query parameters
- `sanitizeExtras(map)` — PII detection on intent extras / share data
- `detectLeaks(data)` — returns list of PII types found
- `validateShareData(data)` — null if safe, PII types if unsafe

##### 16. Screenshot Watermark Shield
- `WatermarkOverlay` widget — repeating invisible watermark pattern
- Configurable: opacity (default 0.03), font size, rotation angle, color
- `WatermarkShield.instance.configure(text: 'user@example.com')` for global config
- Alternative to blocking: allow screenshots but trace leakers

##### 17. Dependency Integrity Shield
- `registerHashes(map)` — store expected package checksums
- `verifyLockfile(path)` — validate pubspec.lock against expected hashes
- Intended for CI/CD integration

##### 18. Code Injection Detection Shield
- **Android:** Scans for unexpected .dex/.jar files in app directory, suspicious strings in /proc/self/maps
- **iOS/macOS:** DYLD_INSERT_LIBRARIES detection + suspicious dylib scanning (inject, payload, exploit, backdoor, trojan, keylog)
- **Windows:** EnumProcessModules for suspicious DLL names
- **Linux:** LD_PRELOAD + /proc/self/maps scanning
- API: `CodeInjectionShield.checkCodeInjection()`, `getSuspiciousModules()`

##### 19. Obfuscation Health Check Shield
- Runtime class name check: detects if ProGuard/obfuscation was applied
- `ObfuscationShield.isObfuscated()` — native platform check
- `checkDartSymbols()` — verifies Dart class names are mangled

##### 20. Security Dashboard Widget
- `SecurityDashboard()` — Material Card showing all 10 RASP check results
- Color-coded: green (safe) / red (detected) per check
- Refresh button for on-demand re-scan
- Debug-only widget for development/QA verification

#### Architecture

- **Zero breaking changes** — all new features are in separate files
- **New method channel constants** — 16 new XOR-encoded method names in `ShieldCodec`
- **3 new platform channels** — `secure_storage`, `biometric`, `device_binding`
- **New native files:** 8 Android (Kotlin), 9 iOS (Swift), 7 macOS (Swift), 14 Windows (C++), 14 Linux (C++)
- **Version:** 1.11.0 → 2.0.0

---

## 1.11.0

### Location Shield — Native-Level Fake Location Detection

New `LocationShield` module with 7-layer defense-in-depth detection of GPS spoofing, mock locations, and location manipulation across all 6 platforms.

#### Detection Layers

1. **Mock Provider Detection** — Platform settings, API flags (`isMock`, developer settings, test providers)
2. **Spoofing App Detection** — Scans for 30+ known GPS spoofing apps/packages (Android), jailbreak location tweaks/dylibs (iOS)
3. **Location Hook Detection** — Detects Xposed/Frida hooks on `LocationManager` (Android), Obj-C method swizzling on `CLLocation`/`CLLocationManager` (iOS), ARM64 inline trampolines, PLT/GOT hooks, `/proc/self/maps` analysis
4. **GPS Signal Anomaly Detection** — GNSS satellite SNR uniformity analysis, constellation diversity check, impossible satellite counts (Android); CLLocation property consistency analysis (iOS)
5. **Sensor Fusion Correlation** — Cross-correlates GPS movement with accelerometer/gyroscope/barometer/pedometer data; detects physics-violating spoofs where GPS says moving but sensors say stationary
6. **Temporal Anomaly Detection** — Detects impossible speed (teleportation), altitude impossibility, bearing reversal at speed, GPS/system time drift, coordinate repetition (replay attacks), grid pattern detection
7. **Environment Integrity Check** — Weighted aggregation of all layers with cross-validation amplification; integrates with existing RASP detectors (root/Frida/hooks amplify location spoof scores)

#### Platform Coverage

* **Android (Kotlin):** Full 7 layers with GNSS callbacks, `/proc` inspection, reflection hook detection, sensor fusion
* **iOS (Swift):** Full 7 layers with CoreMotion, `dladdr` swizzle detection, ARM64 trampoline scanning, dylib injection scan
* **macOS (Swift):** 4 layers (mock provider, hook detection, temporal anomaly, integrity)
* **Windows (C++):** 4 layers (mock provider, spoofing process detection, IAT hook detection, integrity)
* **Linux (C++):** 4 layers (mock provider, LD_PRELOAD hooks, `/proc/self/maps`, spoofing process detection)
* **Web/WASM:** Geolocation API override detection, prototype tampering check

#### API

* `LocationShield.instance.checkLocationAuthenticity()` — One-shot 7-layer check returning `LocationVerdict`
* `LocationShield.instance.monitorLocation()` — Continuous monitoring stream
* `LocationShield.instance.checkSpoofingApps()` — Check for installed spoofing apps (no location permission needed)
* `LocationShield.instance.isMockLocationEnabled()` — Check developer settings (no location permission needed)
* `LocationShield.instance.validateLocation()` — Validate externally-obtained coordinates
* `LocationShield.instance.fullLocationSecurityScan()` — Combined RASP + Location scan with cross-referencing

#### Anti-Bypass Design

* Native-level checks run below Dart VM — hooking Dart doesn't affect native detectors
* All channel/method names XOR-encoded (anti-reverse-engineering)
* Fail-closed design — platform errors default to "threat detected"
* Cross-detector validation — disabling one layer raises suspicion in others
* Sensor fusion validates physics — can't fake accelerometer + gyro + barometer + GPS simultaneously

## 1.10.0

### Anti-Reverse-Engineering Hardening

Comprehensive hardening of the plugin binary across all 6 platforms to resist static analysis, dynamic hooking, and repackaging attacks.

#### P0: XOR String Encoding (All Platforms)

* **Dart:** Created `ShieldCodec` utility — all MethodChannel names and method names are stored as XOR-encoded byte arrays and decoded at runtime. No plaintext channel/method strings in compiled Dart output.
* **Android (Kotlin):** `ShieldCodec.kt` — all channel registrations and method dispatch use runtime-decoded strings.
* **iOS (Swift):** `ShieldCodec.swift` — plugin entry point and all RASP detectors use encoded strings.
* **macOS (Swift):** `ShieldCodec.swift` — same encoding as iOS.
* **Windows (C++):** `shield_codec.h` — `ShieldCodec::Decode()` replaces all plaintext detection strings in RASP detectors.
* **Linux (C++):** `shield_codec.h` — same C++ codec, all detector string literals replaced.
* **Web:** `flutter_neo_shield_web.dart` rewritten with cached decoded method names and if-else dispatch (no plaintext switch cases).

#### P1: ProGuard & Native String Encryption

* **Android ProGuard:** Added `proguard-rules.pro` and `consumer-proguard-rules.pro` — obfuscates all internal detector classes, keeps only the public plugin entry point.
* **Native detection strings:** File paths, process names, registry keys, and other detection indicators in Windows/Linux/iOS/macOS/Android RASP detectors replaced with XOR-encoded equivalents.

#### P2: Build-Level Hardening

* **iOS/macOS podspecs:** Added `pod_target_xcconfig` with `-Os` optimization, dead code stripping, symbol stripping, and debug symbol removal.
* **Windows CMakeLists.txt:** Added `/O2`, `/GL` (whole program optimization), Link-Time Code Generation, static runtime linking.
* **Linux CMakeLists.txt:** Added `-O2`, `-fvisibility=hidden`, `--strip-all`, `--gc-sections` (dead code elimination).

#### P3: Self-Protection & Fail-Safety

* **Android `SelfIntegrityChecker`:** Verifies classloader chain integrity, scans stack traces for hook frameworks (Xposed/Frida/Substrate), checks class hierarchy for injected superclasses.
* **iOS `SelfIntegrityChecker`:** Detects ObjC method swizzling on `FlutterNeoShieldPlugin`, checks `DYLD_INSERT_LIBRARIES` injection, scans for suspicious ObjC classes (Substrate, Frida, Cydia).
* **Cross-detector validation (Android/iOS):** If self-integrity check fails, all individual detector results are overridden to "detected" — prevents selective hook bypasses.
* **Fail-closed exception handling:** Fixed catch blocks across 15+ detector methods on Android, macOS, Windows, and Linux to return `true` (threat detected) instead of `false` (safe) on exceptions.

#### Other Changes

* **Version:** 1.9.0 → 1.10.0
* **iOS podspec version:** Synced to 1.10.0 (was 0.9.0).
* **README:** Added Anti-Reverse-Engineering Hardening section with app-level `--obfuscate` recommendation.
* **All 338 tests pass.** Zero Dart analysis issues.

---

## 1.9.0

### Native RASP, Screen Shield & Memory Shield on All 6 Platforms + WASM Support

All security features now run in **native code** on every platform — macOS (Swift), Windows (C++), Linux (C++), and Web (JavaScript via `dart:js_interop`). No more Dart-side stubs or fallbacks for desktop/web.

#### Native Desktop Plugins (macOS, Windows, Linux)

All 10 RASP checks, screen protection, and secure memory wipe are now implemented natively:

* **macOS (Swift):**
  * RASP: `sysctl P_TRACED`, `ptrace PT_DENY_ATTACH`, IOKit VM detection, `SecCodeCopySelf` + `SecStaticCodeCheckValidity`, `SCDynamicStoreCopyProxies`, `_dyld_image_count` hook scanning, Frida port/file/dylib detection, `getifaddrs` VPN interfaces.
  * Screen: `NSWindow.sharingType = .none` (OS-level capture exclusion), `CGWindowListCopyWindowInfo` recording detection.
  * Memory: `Data.resetBytes` secure wipe via MethodChannel.

* **Windows (C++):**
  * RASP: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess` (ProcessDebugPort/ProcessDebugObjectHandle), CPUID hypervisor bit, SMBIOS firmware table, `WinVerifyTrust` Authenticode, `WinHttpGetIEProxyConfigForCurrentUser`, `GetAdaptersInfo` VPN detection, DR0-DR3 hardware breakpoint registers.
  * Screen: `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` with `WDA_MONITOR` fallback.
  * Memory: `SecureZeroMemory` secure wipe via MethodChannel.
  * Links: wintrust, crypt32, ws2_32, iphlpapi, psapi, ntdll.

* **Linux (C++):**
  * RASP: `/proc/self/status` TracerPid, `PTRACE_TRACEME`, `/sys/class/dmi/id` VM detection, `systemd-detect-virt`, `LD_PRELOAD`/`LD_LIBRARY_PATH`/`LD_AUDIT` injection detection, ELF magic verification, `/proc/self/exe` inode comparison, `getifaddrs` VPN interfaces (tun/tap/ppp/wg).
  * Screen: Best-effort (Linux has no universal capture prevention API).
  * Memory: `explicit_bzero` secure wipe via MethodChannel.

#### Native Web Plugin (WASM-Compatible)

* **Rewrote** `flutter_neo_shield_web.dart` using `package:web` + `dart:js_interop` — fully compatible with both **JavaScript and WASM** compilation targets.
* Replaced deprecated `dart:html` / `dart:js` (JS-only) with modern WASM-safe APIs.
* All JS interop goes through `@JS('eval') external JSAny? _jsEval()` binding.
* **Web RASP checks:**
  * Debugger/DevTools: Window outer/inner size diff heuristic (docked panel detection).
  * Emulator: `navigator.webdriver`, HeadlessChrome UA, automation global properties, empty `navigator.languages`.
  * Hooks: Native function `toString()` check for `[native code]` (fetch, XMLHttpRequest, eval, Promise, JSON.parse/stringify, Function).
  * Integrity: Cross-origin `<script>` injection, excessive inline script count.
  * Signature: `Function.prototype.bind`, `Object.prototype.toString`, `Array.prototype.push` tampering.
  * Native Debug: Computation timing anomaly detection.
  * Network Threats: WebRTC availability check (`RTCPeerConnection` blocked by VPN/privacy extensions).
  * Root/Frida: N/A on web — always returns `false`.
* **Web Screen Protection:** CSS-based (`user-select: none`, `@media print { body { display: none } }`, context menu prevention, Ctrl+P blocking).
* **Web Memory Shield:** In-memory Dart store with zero-fill wipe.

#### SDK & Dependency Changes

* **Minimum Dart SDK:** `>=3.0.0` → `>=3.3.0` (required for `dart:js_interop` / WASM support).
* **Minimum Flutter:** `>=3.0.0` → `>=3.19.0`.
* **New dependency:** `web: ^1.0.0` (replaces `dart:html` for WASM compatibility).
* **iOS podspec version** synced to `1.9.0` (was stuck at `0.2.0`).

#### Plugin Architecture

* **pubspec.yaml:** Desktop platforms now register native plugin classes instead of Dart stubs:
  * macOS: `pluginClass: FlutterNeoShieldPlugin` (Swift)
  * Windows: `pluginClass: FlutterNeoShieldPluginCApi` (C++)
  * Linux: `pluginClass: FlutterNeoShieldPlugin` (C++ / GObject)
* **Removed** desktop stub classes from `flutter_neo_shield_stub.dart` — all platforms now use native plugins.
* All native plugins register handlers on the same MethodChannel names (`com.neelakandan.flutter_neo_shield/rasp`, `/screen`, `/memory`) — zero Dart-side changes required.

#### README Updated

* Platform support table updated: all 6 platforms now show native RASP, Screen Shield, and Memory Shield support.
* Added per-platform detection details for Signature, Native Debug, and Network Threat checks.
* Added desktop screen protection mechanism descriptions.
* Updated Screen Shield FAQ.

---

## 0.8.0

### P0 Anti-Reverse-Engineering: Signature, Native Debug, and Network Threat Detection

Three new native-level RASP detectors targeting the most critical desktop-based APK/IPA reverse engineering attacks.

#### New: APK/IPA Signature Verification (`SignatureDetector`)

* **Android:** Reads the APK signing certificate at runtime and checks for:
  * Debug certificate (`CN=Android Debug`) — re-signed with default debug keystore.
  * Multiple signers — anomaly for production apps.
  * Optional SHA-256 hash comparison against a known-good certificate.
  * Optional `classes.dex` hash verification to detect bytecode patching.
* **iOS:** Verifies code signature integrity via:
  * `_CodeSignature/CodeResources` existence and parse check.
  * `get-task-allow` entitlement detection (should be false in production).
  * `DYLD_INSERT_LIBRARIES` / `DYLD_LIBRARY_PATH` environment variable detection.
* **New Dart class:** `SignatureDetector` in `lib/src/rasp/signature_detector.dart`.
* **New native classes:** `SignatureDetector.kt` (Android), `SignatureDetector_P0.swift` (iOS).
* **Helper:** `RaspShield.getSignatureHash()` returns the current signing certificate SHA-256 hash for embedding in your app.

#### New: Native Debugger Detection (`NativeDebugDetector`)

* **Android:** Catches GDB, LLDB, and strace attached from desktop via ADB:
  * `/proc/self/status` TracerPid check — non-zero means ptrace-attached.
  * `/proc/self/wchan` check — detects `ptrace_stop` wait state.
  * Timing anomaly detection — single-stepping causes measurable delays.
* **iOS:** Deeper than the existing P_TRACED sysctl check:
  * Mach exception port enumeration — debuggers register exception ports.
  * Timing anomaly detection — same as Android.
  * `PT_DENY_ATTACH` support via `NativeDebugDetector.denyDebuggerAttachment()`.
* **New Dart class:** `NativeDebugDetector` in `lib/src/rasp/native_debug_detector.dart`.
* **New native classes:** `NativeDebugDetector.kt` (Android), `NativeDebugDetector.swift` (iOS).

#### New: Proxy & VPN Detection (`NetworkThreatDetector`)

* **Android:** Detects MITM setups used during APK reverse engineering:
  * `System.getProperty("http.proxyHost")` and `https.proxyHost`.
  * `ConnectivityManager.getLinkProperties().httpProxy` (API 23+).
  * `Settings.Global.HTTP_PROXY` global setting.
  * `NetworkCapabilities.TRANSPORT_VPN` active transport check.
  * Network interface enumeration for `tun0`, `ppp0`, `tap0`, `ipsec` prefixes.
* **iOS:** Detects proxy and VPN via:
  * `CFNetworkCopySystemProxySettings` — HTTP, HTTPS, and SOCKS proxy.
  * Network interface enumeration for `utun`, `ppp`, `ipsec`, `tap`, `tun` prefixes.
* **New Dart class:** `NetworkThreatDetector` in `lib/src/rasp/network_threat_detector.dart`.
* **New native classes:** `NetworkThreatDetector.kt` (Android), `NetworkThreatDetector.swift` (iOS).

#### SecurityReport Updated

* Three new fields: `signatureTampered`, `nativeDebugDetected`, `networkThreatDetected` (all default `false`).
* Zero breaking changes — existing callers are unaffected.
* `isSafe` now includes all 10 checks.
* `fullSecurityScan()` now runs all 10 checks in parallel.

#### RaspChannel Updated

* New `invokeStringMethod()` for methods returning String data (e.g., `getSignatureHash`).

#### Example App Updated

* RASP Shield demo now displays all 10 detection results including the 3 new checks.

---

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
