## 0.4.1

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
