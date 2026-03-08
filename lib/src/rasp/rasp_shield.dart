import 'dart:developer' as developer;

import 'debugger_detector.dart';
import 'developer_mode_detector.dart';
import 'emulator_detector.dart';
import 'frida_detector.dart';
import 'hook_detector.dart';
import 'integrity_detector.dart';
import 'root_detector.dart';
import 'security_mode.dart';
import 'security_result.dart';

/// Runtime App Self Protection (RASP) main interface.
///
/// Provides individual and full-scan security checks with configurable
/// response modes via [SecurityMode].
class RaspShield {
  RaspShield._();

  /// Checks for active debuggers.
  static Future<SecurityResult> checkDebugger() => DebuggerDetector.check();

  /// Checks for device rooted / jailbreak status.
  static Future<SecurityResult> checkRoot() => RootDetector.check();

  /// Checks if running inside an emulator.
  static Future<SecurityResult> checkEmulator() => EmulatorDetector.check();

  /// Checks for Frida injection.
  static Future<SecurityResult> checkFrida() => FridaDetector.check();

  /// Checks for hooking frameworks (Xposed, Substrate, Magisk modules).
  static Future<SecurityResult> checkHooks() => HookDetector.check();

  /// Checks application binary integrity against tampering.
  static Future<SecurityResult> checkIntegrity() => IntegrityDetector.check();

  /// Checks if Developer Options (Android) or Developer Mode (iOS 16+) is enabled.
  static Future<SecurityResult> checkDeveloperMode() =>
      DeveloperModeDetector.check();

  /// Perform a full security scan returning all results.
  ///
  /// All checks run in parallel to minimise the TOCTOU window
  /// (time-of-check to time-of-use).
  ///
  /// When [mode] is [SecurityMode.strict], a [SecurityException] is
  /// thrown if any threat is detected. When [mode] is [SecurityMode.warn],
  /// a warning is logged. When [mode] is [SecurityMode.custom], the
  /// [onThreat] callback is invoked with the report.
  static Future<SecurityReport> fullSecurityScan({
    SecurityMode mode = SecurityMode.silent,
    void Function(SecurityReport report)? onThreat,
  }) async {
    final results = await Future.wait([
      checkDebugger(),
      checkRoot(),
      checkEmulator(),
      checkFrida(),
      checkHooks(),
      checkIntegrity(),
      checkDeveloperMode(),
    ]);

    final report = SecurityReport(
      debuggerDetected: results[0].isDetected,
      rootDetected: results[1].isDetected,
      emulatorDetected: results[2].isDetected,
      fridaDetected: results[3].isDetected,
      hookDetected: results[4].isDetected,
      integrityTampered: results[5].isDetected,
      developerModeDetected: results[6].isDetected,
    );

    if (!report.isSafe) {
      switch (mode) {
        case SecurityMode.strict:
          throw SecurityException(
            'Security threats detected: $report',
          );
        case SecurityMode.warn:
          developer.log(
            'RASP WARNING: $report',
            name: 'RaspShield',
          );
        case SecurityMode.custom:
          onThreat?.call(report);
        case SecurityMode.silent:
          break;
      }
    }

    return report;
  }
}
