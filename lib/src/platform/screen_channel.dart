import 'dart:async';
import 'package:flutter/services.dart';
import 'dart:developer' as developer;

/// Handles communication between Flutter and native layer for Screen Shield.
///
/// Provides methods to enable/disable screen protection and streams for
/// screenshot and recording detection events.
class ScreenChannel {
  static const MethodChannel _channel =
      MethodChannel('com.neelakandan.flutter_neo_shield/screen');

  static const EventChannel _eventChannel =
      EventChannel('com.neelakandan.flutter_neo_shield/screen_events');

  static Stream<dynamic>? _eventStream;

  /// Lazily initializes and returns the broadcast event stream.
  static Stream<dynamic> get _events {
    _eventStream ??= _eventChannel.receiveBroadcastStream();
    return _eventStream!;
  }

  /// Enable screen protection (screenshots + recording).
  static Future<bool> enableProtection() async {
    try {
      final result =
          await _channel.invokeMethod<bool>('enableScreenProtection');
      return result ?? false;
    } on MissingPluginException {
      developer.log(
        'enableScreenProtection: native plugin not registered — '
        'screen protection unavailable on this platform',
        name: 'ScreenChannel',
      );
      return false;
    } on PlatformException catch (e) {
      developer.log(
        'Failed to enable screen protection: ${e.message}',
        name: 'ScreenChannel',
      );
      return false;
    }
  }

  /// Disable screen protection.
  static Future<bool> disableProtection() async {
    try {
      final result =
          await _channel.invokeMethod<bool>('disableScreenProtection');
      return result ?? false;
    } on MissingPluginException {
      developer.log(
        'disableScreenProtection: native plugin not registered',
        name: 'ScreenChannel',
      );
      return false;
    } on PlatformException catch (e) {
      developer.log(
        'Failed to disable screen protection: ${e.message}',
        name: 'ScreenChannel',
      );
      return false;
    }
  }

  /// Query whether screen protection is currently active.
  static Future<bool> isProtectionActive() async {
    try {
      final result =
          await _channel.invokeMethod<bool>('isScreenProtectionActive');
      return result ?? false;
    } on MissingPluginException {
      return false;
    } on PlatformException catch (e) {
      developer.log(
        'Failed to query screen protection state: ${e.message}',
        name: 'ScreenChannel',
      );
      return false;
    }
  }

  /// Enable app switcher guard (blur/hide content in recent apps).
  static Future<bool> enableAppSwitcherGuard() async {
    try {
      final result =
          await _channel.invokeMethod<bool>('enableAppSwitcherGuard');
      return result ?? false;
    } on MissingPluginException {
      developer.log(
        'enableAppSwitcherGuard: native plugin not registered',
        name: 'ScreenChannel',
      );
      return false;
    } on PlatformException catch (e) {
      developer.log(
        'Failed to enable app switcher guard: ${e.message}',
        name: 'ScreenChannel',
      );
      return false;
    }
  }

  /// Disable app switcher guard.
  static Future<bool> disableAppSwitcherGuard() async {
    try {
      final result =
          await _channel.invokeMethod<bool>('disableAppSwitcherGuard');
      return result ?? false;
    } on MissingPluginException {
      developer.log(
        'disableAppSwitcherGuard: native plugin not registered',
        name: 'ScreenChannel',
      );
      return false;
    } on PlatformException catch (e) {
      developer.log(
        'Failed to disable app switcher guard: ${e.message}',
        name: 'ScreenChannel',
      );
      return false;
    }
  }

  /// Query whether the screen is currently being recorded.
  static Future<bool> isScreenBeingRecorded() async {
    try {
      final result = await _channel.invokeMethod<bool>('isScreenBeingRecorded');
      return result ?? false;
    } on MissingPluginException {
      return false;
    } on PlatformException catch (e) {
      developer.log(
        'Failed to query recording state: ${e.message}',
        name: 'ScreenChannel',
      );
      return false;
    }
  }

  /// Stream of events from native side.
  ///
  /// Events are maps with a "type" key:
  /// - `{"type": "screenshot"}` — screenshot was taken (iOS)
  /// - `{"type": "recording", "isRecording": bool}` — recording state changed
  static Stream<dynamic> get events => _events;

  /// Resets the event stream. Only for testing.
  static void resetForTesting() {
    _eventStream = null;
  }
}
