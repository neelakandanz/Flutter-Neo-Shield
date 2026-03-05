import 'package:flutter/services.dart';
import 'dart:developer' as developer;

/// Handles communication between Flutter and Native layer for RASP checks.
///
/// Uses a fail-closed design: if the native platform is unavailable or
/// throws an error, checks report the threat as detected (safe default).
class RaspChannel {
  static const MethodChannel _channel =
      MethodChannel('com.neelakandan.flutter_neo_shield/rasp');

  /// Whether to fail closed (return true = detected) on platform errors.
  ///
  /// Defaults to true for security. Set to false only in development
  /// when native plugins are not yet integrated.
  static bool failClosed = true;

  /// Invoke a native detection method.
  ///
  /// Returns true (threat detected) when the platform channel is
  /// unavailable and [failClosed] is true, ensuring the app does not
  /// silently pass security checks on unsupported platforms.
  static Future<bool> invokeDetection(String method,
      [Map<String, dynamic>? arguments]) async {
    try {
      final result = await _channel.invokeMethod<bool>(method, arguments);
      return result ?? failClosed;
    } on MissingPluginException {
      developer.log(
        '$method: native plugin not registered — '
        '${failClosed ? "reporting as detected (fail-closed)" : "reporting as safe (fail-open)"}',
        name: 'RaspChannel',
      );
      return failClosed;
    } on PlatformException catch (e) {
      developer.log('Failed to execute $method: ${e.message}',
          name: 'RaspChannel');
      return failClosed;
    }
  }
}
