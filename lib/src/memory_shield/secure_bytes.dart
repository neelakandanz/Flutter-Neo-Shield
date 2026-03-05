/// Secure byte array container with wipe-on-dispose.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:meta/meta.dart';

import 'memory_shield.dart';

/// A secure container for sensitive byte arrays that overwrites on dispose.
///
/// Ideal for encryption keys, binary secrets, and other sensitive byte data.
///
/// **Security note:** Each call to [bytes] returns a new copy that is not
/// tracked or wiped. Prefer [useOnce] to limit the number of copies.
/// See [SecureString] for additional caveats about Dart VM memory.
///
/// **Important:** You MUST call [dispose] when done, or use [useOnce]
/// for one-time-use secrets.
///
/// ```dart
/// final key = SecureBytes(Uint8List.fromList([1, 2, 3, 4]));
/// print(key.bytes); // [1, 2, 3, 4]
/// key.dispose();
/// // key.bytes now throws StateError
/// ```
class SecureBytes implements SecureDisposable {
  /// Creates a [SecureBytes] containing a copy of the given [bytes].
  ///
  /// ```dart
  /// final key = SecureBytes(Uint8List.fromList([1, 2, 3, 4]));
  /// ```
  SecureBytes(Uint8List bytes, {this.maxAge})
      : _bytes = Uint8List.fromList(bytes),
        createdAt = DateTime.now() {
    _id = 'sb_${createdAt.microsecondsSinceEpoch}_${identityHashCode(this)}';
    MemoryShield().register(this);
    _tryPlatformAllocate();

    final effectiveMaxAge = maxAge ?? MemoryShield().config.defaultMaxAge;
    if (effectiveMaxAge != null) {
      _autoDisposeTimer = Timer(effectiveMaxAge, dispose);
    }
  }

  /// Creates a [SecureBytes] from a base64-encoded string.
  ///
  /// ```dart
  /// final key = SecureBytes.fromBase64('AQIDBA==');
  /// ```
  SecureBytes.fromBase64(String base64String, {Duration? maxAge})
      : this(Uint8List.fromList(base64Decode(base64String)), maxAge: maxAge);

  final Uint8List _bytes;
  bool _isDisposed = false;
  late final String _id;
  Timer? _autoDisposeTimer;

  /// When this secure container was created.
  final DateTime createdAt;

  /// Optional maximum age before auto-disposal.
  final Duration? maxAge;

  /// Whether this container has been disposed.
  bool get isDisposed => _isDisposed;

  /// The length of the stored byte array.
  int get length => _bytes.length;

  /// Returns a copy of the stored bytes.
  ///
  /// Throws [StateError] if already disposed.
  ///
  /// ```dart
  /// final data = key.bytes; // Uint8List
  /// ```
  Uint8List get bytes {
    if (_isDisposed) {
      throw StateError('SecureBytes has been disposed');
    }
    return Uint8List.fromList(_bytes);
  }

  /// The internal identifier for platform channel operations.
  @visibleForTesting
  String get id => _id;

  /// Disposes this container, overwriting internal bytes with zeros.
  ///
  /// Safe to call multiple times (idempotent).
  ///
  /// ```dart
  /// key.dispose();
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

  /// Executes [action] with the bytes, then immediately disposes.
  ///
  /// ```dart
  /// final result = key.useOnce((bytes) => encrypt(bytes, data));
  /// ```
  T useOnce<T>(T Function(Uint8List bytes) action) {
    try {
      return action(bytes);
    } finally {
      dispose();
    }
  }

  /// Returns the bytes as a base64-encoded string.
  ///
  /// Does NOT dispose the container.
  ///
  /// ```dart
  /// final b64 = key.toBase64(); // 'AQIDBA=='
  /// ```
  String toBase64() {
    if (_isDisposed) {
      throw StateError('SecureBytes has been disposed');
    }
    return base64Encode(_bytes);
  }

  void _tryPlatformAllocate() {
    if (!MemoryShield().config.enablePlatformWipe) return;

    MemoryShield.channel.invokeMethod<void>('allocateSecure', {
      'id': _id,
      'data': _bytes,
    }).catchError((_) {
      // Platform channel unavailable.
    });
  }

  void _tryPlatformWipe() {
    if (!MemoryShield().config.enablePlatformWipe) return;

    MemoryShield.channel.invokeMethod<void>('wipeSecure', {
      'id': _id,
    }).catchError((_) {
      // Platform channel unavailable.
    });
  }
}
