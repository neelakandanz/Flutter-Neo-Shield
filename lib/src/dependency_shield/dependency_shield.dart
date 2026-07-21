import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';

/// Dependency Integrity Shield — verifies dependency files against
/// known-good **SHA-256** checksums.
///
/// Register expected hashes (hex-encoded SHA-256) with [registerHashes], then
/// call [verifyLockfile] to confirm a file still matches. Compute a file's
/// current hash with [computeFileHash].
class DependencyShield {
  DependencyShield._();

  /// Singleton instance of [DependencyShield].
  static final DependencyShield instance = DependencyShield._();

  final Map<String, String> _expectedHashes = {};

  /// Registers expected SHA-256 [hashes] keyed by file name or path
  /// (e.g. `{'pubspec.lock': '<hex sha256>'}`).
  void registerHashes(Map<String, String> hashes) =>
      _expectedHashes.addAll(hashes);

  /// Computes the hex-encoded SHA-256 hash of the file at [path].
  ///
  /// Returns `null` on web or if the file cannot be read.
  Future<String?> computeFileHash(String path) async {
    if (kIsWeb) return null;
    try {
      final bytes = await File(path).readAsBytes();
      return sha256.convert(bytes).toString();
    } catch (_) {
      return null;
    }
  }

  /// Verifies the lockfile at [lockfilePath] against its registered SHA-256 hash.
  ///
  /// The registered key is resolved as: the exact [lockfilePath], else the file
  /// name portion of it, else `'pubspec.lock'`. Returns a map of failures
  /// (key → error message); an empty map means the file matches (or no hash was
  /// registered for it).
  Future<Map<String, String>> verifyLockfile(String lockfilePath) async {
    if (kIsWeb) return {};
    final failures = <String, String>{};

    final fileName = lockfilePath.split(RegExp(r'[\\/]')).last;
    final String key;
    if (_expectedHashes.containsKey(lockfilePath)) {
      key = lockfilePath;
    } else if (_expectedHashes.containsKey(fileName)) {
      key = fileName;
    } else {
      key = 'pubspec.lock';
    }
    if (!_expectedHashes.containsKey(key)) return failures;

    try {
      final bytes = await File(lockfilePath).readAsBytes();
      final hash = sha256.convert(bytes).toString();
      final expected = _expectedHashes[key]!;
      if (expected.trim().toLowerCase() != hash.toLowerCase()) {
        failures[key] = 'Hash mismatch: expected $expected, got $hash';
      }
    } catch (e) {
      failures[key] = 'Failed to read: $e';
    }
    return failures;
  }

  /// Clears all registered expected hashes.
  void reset() => _expectedHashes.clear();
}
