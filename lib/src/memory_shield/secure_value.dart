/// Generic secure value container with wipe-on-dispose.
library;

import 'dart:async';

import 'package:meta/meta.dart';

import 'memory_shield.dart';

/// A generic secure container for any sensitive value with auto-dispose.
///
/// Holds a value of type [T] and optionally calls a custom wiper function
/// on dispose for type-specific cleanup.
///
/// ```dart
/// final secret = SecureValue<Map<String, String>>(
///   {'key': 'value'},
///   wiper: (map) => map.clear(),
/// );
/// print(secret.value); // {'key': 'value'}
/// secret.dispose();
/// ```
class SecureValue<T> implements SecureDisposable {
  /// Creates a [SecureValue] holding the given [value].
  ///
  /// The optional [wiper] function is called on dispose to perform
  /// type-specific cleanup. The optional [maxAge] sets auto-dispose.
  ///
  /// ```dart
  /// final token = SecureValue<String>('abc123', maxAge: Duration(minutes: 5));
  /// ```
  SecureValue(T value, {this.maxAge, this.wiper})
      : _value = value,
        createdAt = DateTime.now() {
    MemoryShield().register(this);

    final effectiveMaxAge = maxAge ?? MemoryShield().config.defaultMaxAge;
    if (effectiveMaxAge != null) {
      _autoDisposeTimer = Timer(effectiveMaxAge, dispose);
    }
  }

  T? _value;
  bool _isDisposed = false;
  Timer? _autoDisposeTimer;

  /// Optional custom wiper function called on dispose.
  final void Function(T)? wiper;

  /// Optional maximum age before auto-disposal.
  final Duration? maxAge;

  /// When this secure container was created.
  final DateTime createdAt;

  /// Whether this container has been disposed.
  bool get isDisposed => _isDisposed;

  /// Returns the stored value.
  ///
  /// Throws [StateError] if already disposed.
  ///
  /// ```dart
  /// print(secret.value); // the stored value
  /// ```
  T get value {
    if (_isDisposed) {
      throw StateError('SecureValue has been disposed');
    }
    return _value as T;
  }

  /// Disposes this container, calling the wiper and nulling the reference.
  ///
  /// Safe to call multiple times (idempotent).
  ///
  /// ```dart
  /// secret.dispose();
  /// ```
  @override
  @mustCallSuper
  void dispose() {
    if (_isDisposed) return;
    _isDisposed = true;
    _autoDisposeTimer?.cancel();
    _autoDisposeTimer = null;

    try {
      if (wiper != null && _value != null) {
        wiper!(_value as T);
      }
    } finally {
      _value = null;
      MemoryShield().unregister(this);
    }
  }

  /// Executes [action] with the value, then immediately disposes.
  ///
  /// ```dart
  /// final result = secret.useOnce((val) => process(val));
  /// ```
  R useOnce<R>(R Function(T value) action) {
    try {
      return action(value);
    } finally {
      dispose();
    }
  }
}
