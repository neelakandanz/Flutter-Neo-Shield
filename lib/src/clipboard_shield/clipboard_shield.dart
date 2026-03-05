/// Main ClipboardShield class for secure clipboard management.
library;

import 'dart:async';

import 'package:flutter/services.dart';
import 'package:meta/meta.dart';

import '../core/pii_detector.dart';
import '../log_shield/safe_log.dart';
import 'clipboard_copy_result.dart';
import 'clipboard_shield_config.dart';

/// Singleton clipboard protection manager.
///
/// Detects PII when copying, starts auto-clear timers, and provides
/// stream-based notifications for clipboard events.
///
/// ```dart
/// ClipboardShield().init(ClipboardShieldConfig(
///   defaultExpiry: Duration(seconds: 15),
/// ));
///
/// final result = await ClipboardShield().copy('john@test.com');
/// print(result.piiType); // PIIType.email
/// ```
class ClipboardShield {
  /// Returns the singleton [ClipboardShield] instance.
  factory ClipboardShield() => _instance;

  ClipboardShield._internal();

  static final ClipboardShield _instance = ClipboardShield._internal();

  ClipboardShieldConfig _config = const ClipboardShieldConfig();
  Timer? _autoClearTimer;
  DateTime? _clearAt;

  final StreamController<void> _clearedController =
      StreamController<void>.broadcast();
  final StreamController<ClipboardCopyResult> _copiedController =
      StreamController<ClipboardCopyResult>.broadcast();

  /// Initializes the ClipboardShield with the given [config].
  ///
  /// ```dart
  /// ClipboardShield().init(ClipboardShieldConfig(
  ///   defaultExpiry: Duration(seconds: 15),
  ///   clearAfterPaste: true,
  /// ));
  /// ```
  void init(ClipboardShieldConfig config) {
    _config = config;
  }

  /// The current configuration.
  ClipboardShieldConfig get config => _config;

  /// Stream that fires when the clipboard is auto-cleared.
  ///
  /// ```dart
  /// ClipboardShield().onCleared.listen((_) {
  ///   print('Clipboard was cleared');
  /// });
  /// ```
  Stream<void> get onCleared => _clearedController.stream;

  /// Stream that fires on each secure copy operation.
  ///
  /// ```dart
  /// ClipboardShield().onCopied.listen((result) {
  ///   print('Copied with PII: ${result.piiDetected}');
  /// });
  /// ```
  Stream<ClipboardCopyResult> get onCopied => _copiedController.stream;

  /// Whether a timed auto-clear is currently pending.
  bool get isActive => _autoClearTimer?.isActive ?? false;

  /// Duration remaining until auto-clear fires.
  ///
  /// Returns [Duration.zero] if no timer is active.
  Duration get remainingTime {
    if (_clearAt == null || !isActive) return Duration.zero;
    final remaining = _clearAt!.difference(DateTime.now());
    return remaining.isNegative ? Duration.zero : remaining;
  }

  /// Copies [text] to the system clipboard with optional auto-clear.
  ///
  /// Returns a [ClipboardCopyResult] with PII detection info and timing.
  ///
  /// ```dart
  /// final result = await ClipboardShield().copy(
  ///   'myP@ssw0rd',
  ///   expireAfter: Duration(seconds: 15),
  /// );
  /// ```
  Future<ClipboardCopyResult> copy(
    String text, {
    Duration? expireAfter,
  }) async {
    try {
      await Clipboard.setData(ClipboardData(text: text));

      // Detect PII.
      final piiType = PIIDetector().getPIIType(text);
      final bool piiDetected = _config.detectPIIOnCopy && piiType != null;

      // Start auto-clear timer.
      final expiry = expireAfter ?? _config.defaultExpiry;
      DateTime? expiresAt;
      Duration? expiresIn;

      // Cancel any existing timer.
      cancelAutoClear();

      if (expiry > Duration.zero) {
        expiresAt = DateTime.now().add(expiry);
        expiresIn = expiry;
        _clearAt = expiresAt;

        _autoClearTimer = Timer(expiry, () {
          clearNow();
          _clearedController.add(null);
          _config.onClearCallback?.call();
        });
      }

      final result = ClipboardCopyResult(
        success: true,
        piiDetected: piiDetected,
        piiType: piiType,
        expiresAt: expiresAt,
        expiresIn: expiresIn,
      );

      _copiedController.add(result);
      _config.onCopyCallback?.call(result);

      if (_config.logCopyEvents) {
        shieldLog(
          'Clipboard: copied text (containsPII: $piiDetected)',
          level: 'DEBUG',
        );
      }

      return result;
    } catch (e) {
      return const ClipboardCopyResult(
        success: false,
        piiDetected: false,
      );
    }
  }

  /// Pastes text from the clipboard and optionally clears it afterward.
  ///
  /// Returns the pasted text, or null if the clipboard is empty.
  ///
  /// ```dart
  /// final text = await ClipboardShield().paste();
  /// ```
  Future<String?> paste() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    final text = data?.text;

    if (text != null && _config.clearAfterPaste) {
      await clearNow();
    }

    return text;
  }

  /// Immediately clears the system clipboard.
  ///
  /// ```dart
  /// await ClipboardShield().clearNow();
  /// ```
  Future<void> clearNow() async {
    _autoClearTimer?.cancel();
    _autoClearTimer = null;
    _clearAt = null;
    await Clipboard.setData(const ClipboardData(text: ''));
  }

  /// Cancels any pending auto-clear timer.
  ///
  /// Use with caution — cancelling the timer means sensitive data will
  /// remain on the clipboard until the next [copy] or [clearNow] call.
  ///
  /// ```dart
  /// ClipboardShield().cancelAutoClear();
  /// ```
  @visibleForTesting
  void cancelAutoClear() {
    _autoClearTimer?.cancel();
    _autoClearTimer = null;
    _clearAt = null;
  }

  /// Resets the ClipboardShield to its default state.
  ///
  /// Cancels any pending timers and resets config.
  ///
  /// ```dart
  /// ClipboardShield().reset();
  /// ```
  void reset() {
    cancelAutoClear();
    _config = const ClipboardShieldConfig();
  }
}
