/// Secure string container with wipe-on-dispose.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:meta/meta.dart';

import 'memory_shield.dart';

/// A secure container for sensitive strings that overwrites content on dispose.
///
/// Since Dart strings are immutable, the string is stored as UTF-8 encoded
/// bytes in a [Uint8List] which can be overwritten with zeros.
///
/// **Security note:** The Dart VM's garbage collector may copy or relocate
/// byte arrays in memory. While [dispose] zero-fills the current buffer,
/// previous GC copies cannot be wiped from Dart. On Android/iOS the native
/// platform channel provides stronger guarantees. On other platforms (Web,
/// desktop) the wipe is best-effort only.
///
/// To minimise leakage, prefer [useOnce] over repeated [value] access,
/// because every call to [value] creates a new immutable Dart [String]
/// that cannot be wiped.
///
/// **Important:** You MUST call [dispose] when done, or use [useOnce]
/// for one-time-use secrets.
///
/// ```dart
/// final secret = SecureString('my-api-key');
/// print(secret.value); // 'my-api-key'
/// secret.dispose();
/// // secret.value now throws StateError
/// ```
class SecureString implements SecureDisposable {
  /// Creates a [SecureString] containing the given [value].
  ///
  /// Optionally set [maxAge] to auto-dispose after a duration.
  ///
  /// ```dart
  /// final secret = SecureString('password123', maxAge: Duration(minutes: 1));
  /// ```
  SecureString(String value, {this.maxAge})
      : _bytes = Uint8List.fromList(utf8.encode(value)),
        _length = value.length,
        createdAt = DateTime.now() {
    _id = 'ss_${createdAt.microsecondsSinceEpoch}_${identityHashCode(this)}';
    MemoryShield().register(this);
    _tryPlatformAllocate();

    final effectiveMaxAge = maxAge ?? MemoryShield().config.defaultMaxAge;
    if (effectiveMaxAge != null) {
      _autoDisposeTimer = Timer(effectiveMaxAge, dispose);
    }
  }

  final Uint8List _bytes;
  final int _length;
  bool _isDisposed = false;
  late final String _id;
  Timer? _autoDisposeTimer;

  /// When this secure string was created.
  final DateTime createdAt;

  /// Optional maximum age before auto-disposal.
  final Duration? maxAge;

  /// Whether this container has been disposed.
  bool get isDisposed => _isDisposed;

  /// The length of the original string.
  int get length => _length;

  /// Returns the stored string value.
  ///
  /// Throws [StateError] if already disposed.
  ///
  /// ```dart
  /// final secret = SecureString('abc');
  /// print(secret.value); // 'abc'
  /// ```
  String get value {
    if (_isDisposed) {
      throw StateError('SecureString has been disposed');
    }
    return utf8.decode(_bytes);
  }

  /// The internal identifier for platform channel operations.
  @visibleForTesting
  String get id => _id;

  /// Disposes this container, overwriting internal bytes with zeros.
  ///
  /// Safe to call multiple times (idempotent).
  ///
  /// ```dart
  /// secret.dispose();
  /// ```
  @override
  void dispose() {
    if (_isDisposed) return;
    _isDisposed = true;
    _autoDisposeTimer?.cancel();
    _autoDisposeTimer = null;

    // Overwrite bytes with zeros.
    for (var i = 0; i < _bytes.length; i++) {
      _bytes[i] = 0;
    }

    _tryPlatformWipe();
    MemoryShield().unregister(this);
  }

  /// Executes [action] with the value, then immediately disposes.
  ///
  /// Use for one-time-use secrets to ensure they are wiped after use.
  ///
  /// ```dart
  /// final hash = SecureString('password').useOnce(
  ///   (val) => computeHash(val),
  /// );
  /// ```
  T useOnce<T>(T Function(String value) action) {
    try {
      return action(value);
    } finally {
      dispose();
    }
  }

  /// Compares [other] to the stored value using constant-time comparison.
  ///
  /// Prevents timing attacks by always comparing all bytes.
  ///
  /// ```dart
  /// secret.matches('test-password'); // true or false
  /// ```
  bool matches(String other) {
    if (_isDisposed) {
      throw StateError('SecureString has been disposed');
    }
    final otherBytes = Uint8List.fromList(utf8.encode(other));
    try {
      if (_bytes.length != otherBytes.length) return false;

      var result = 0;
      for (var i = 0; i < _bytes.length; i++) {
        result |= _bytes[i] ^ otherBytes[i];
      }
      return result == 0;
    } finally {
      // Wipe the comparison bytes to reduce leakage.
      for (var i = 0; i < otherBytes.length; i++) {
        otherBytes[i] = 0;
      }
    }
  }

  void _tryPlatformAllocate() {
    if (!MemoryShield().config.enablePlatformWipe) return;

    MemoryShield.channel.invokeMethod<void>('allocateSecure', {
      'id': _id,
      'data': _bytes,
    }).catchError((_) {
      // Platform channel unavailable — fall back to Dart approach.
    });
  }

  void _tryPlatformWipe() {
    if (!MemoryShield().config.enablePlatformWipe) return;

    MemoryShield.channel.invokeMethod<void>('wipeSecure', {
      'id': _id,
    }).catchError((_) {
      // Platform channel unavailable — Dart-side wipe already done.
    });
  }
}
