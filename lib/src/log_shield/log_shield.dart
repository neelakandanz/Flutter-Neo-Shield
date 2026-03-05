/// Main LogShield class for sanitized logging.
library;

import 'dart:convert';

import 'package:flutter/foundation.dart';

import '../core/pii_detector.dart';
import 'json_sanitizer.dart';
import 'log_shield_config.dart';

/// Singleton log sanitization manager.
///
/// Automatically sanitizes PII from all log output. Drop-in replacement
/// for print() and debugPrint().
///
/// ```dart
/// LogShield().init(LogShieldConfig(silentInRelease: true));
/// LogShield().log('User email: john@test.com');
/// // Output: [INFO] User email: [EMAIL HIDDEN]
/// ```
class LogShield {
  /// Returns the singleton [LogShield] instance.
  factory LogShield() => _instance;

  LogShield._internal();

  static final LogShield _instance = LogShield._internal();

  LogShieldConfig _config = const LogShieldConfig();
  bool _enabled = true;

  /// Whether the log shield is currently enabled.
  bool get isEnabled => _enabled;

  /// Initializes the LogShield with the given [config].
  ///
  /// ```dart
  /// LogShield().init(LogShieldConfig(
  ///   silentInRelease: true,
  ///   showRedactionNotice: true,
  /// ));
  /// ```
  void init(LogShieldConfig config) {
    _config = config;
  }

  /// The current configuration.
  LogShieldConfig get config => _config;

  /// Enables log output.
  ///
  /// ```dart
  /// LogShield().enable();
  /// ```
  void enable() {
    _enabled = true;
  }

  /// Disables all log output.
  ///
  /// ```dart
  /// LogShield().disable();
  /// ```
  void disable() {
    _enabled = false;
  }

  /// Sanitizes and logs a [message] with an optional [level] and [tag].
  ///
  /// In debug mode with `sanitizeInDebug: false` (the default), this works
  /// exactly like `print()` — you see all real values for easy debugging.
  ///
  /// In release mode (or when `sanitizeInDebug: true`), PII is automatically
  /// hidden before printing.
  ///
  /// ```dart
  /// LogShield().log('User email: john@test.com', level: 'INFO');
  /// // Debug output:   [INFO] User email: john@test.com        (real value!)
  /// // Release output:  [INFO] User email: [EMAIL HIDDEN]      (sanitized!)
  /// ```
  void log(String message, {String level = 'INFO', String? tag}) {
    if (!_shouldOutput(level)) return;

    final shouldSanitize = !kDebugMode || _config.sanitizeInDebug;

    String displayMessage;
    int redactedCount = 0;

    if (shouldSanitize) {
      final detector = PIIDetector();
      final matches = detector.detect(message);
      displayMessage = detector.sanitize(message);
      redactedCount = matches.length;
    } else {
      displayMessage = message;
    }

    final buffer = StringBuffer();

    if (_config.showTimestamp) {
      buffer.write('[${DateTime.now().toIso8601String()}] ');
    }

    buffer.write('[$level]');
    if (tag != null) {
      buffer.write(' [$tag]');
    }
    buffer.write(' $displayMessage');

    if (_config.showRedactionNotice && redactedCount > 0) {
      buffer.write(' [LogShield: $redactedCount items redacted]');
    }

    _output(buffer.toString(), level);
  }

  /// Sanitizes and logs a JSON map with a [label].
  ///
  /// ```dart
  /// LogShield().logJson('API Response', {'name': 'John', 'id': 123});
  /// // Output: [INFO] API Response: {"name": "[REDACTED]", "id": 123}
  /// ```
  void logJson(String label, Map<String, dynamic> json) {
    if (!_shouldOutput('INFO')) return;

    final shouldSanitize = !kDebugMode || _config.sanitizeInDebug;

    final outputJson = shouldSanitize ? JsonSanitizer.sanitize(json) : json;
    final jsonStr = const JsonEncoder.withIndent(null).convert(outputJson);

    final buffer = StringBuffer();

    if (_config.showTimestamp) {
      buffer.write('[${DateTime.now().toIso8601String()}] ');
    }

    buffer.write('[INFO] $label: $jsonStr');

    _output(buffer.toString(), 'INFO');
  }

  /// Sanitizes and logs an error [message] with optional [error] and [stackTrace].
  ///
  /// ```dart
  /// LogShield().logError(
  ///   'Login failed for john@test.com',
  ///   error: exception,
  ///   stackTrace: stackTrace,
  /// );
  /// ```
  void logError(String message, {Object? error, StackTrace? stackTrace}) {
    if (!_shouldOutput('ERROR')) return;

    final shouldSanitize = !kDebugMode || _config.sanitizeInDebug;

    final detector = PIIDetector();
    final displayMessage =
        shouldSanitize ? detector.sanitize(message) : message;

    final buffer = StringBuffer();

    if (_config.showTimestamp) {
      buffer.write('[${DateTime.now().toIso8601String()}] ');
    }

    buffer.write('[ERROR] $displayMessage');

    if (error != null) {
      final errorStr = error.toString();
      final displayError =
          shouldSanitize ? detector.sanitize(errorStr) : errorStr;
      buffer.write('\n  Error: $displayError');
    }

    if (stackTrace != null) {
      final stackStr = stackTrace.toString();
      final displayStack =
          shouldSanitize ? detector.sanitize(stackStr) : stackStr;
      buffer.write('\n  StackTrace: $displayStack');
    }

    _output(buffer.toString(), 'ERROR');
  }

  bool _shouldOutput(String level) {
    if (!_enabled) return false;
    if (!_config.isLevelEnabled(level)) return false;
    if (kReleaseMode && _config.silentInRelease) return false;
    if (kProfileMode && _config.silentInProfile) return false;
    return true;
  }

  void _output(String message, String level) {
    if (_config.outputHandler != null) {
      _config.outputHandler!(message, level);
    } else {
      // ignore: avoid_print
      print(message);
    }
  }

  /// Resets the LogShield to its default state.
  ///
  /// Useful in tests.
  ///
  /// ```dart
  /// LogShield().reset();
  /// ```
  void reset() {
    _config = const LogShieldConfig();
    _enabled = true;
  }
}
