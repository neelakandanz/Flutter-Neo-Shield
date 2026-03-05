/// Security detection response types.
///
/// Used by [RaspShield.fullSecurityScan] to determine how to react
/// when a threat is detected.
enum SecurityMode {
  /// Strict restriction — throw [SecurityException] on any detection.
  strict,

  /// Log a warning to the console, allow app execution.
  warn,

  /// Continue silently, handle detection programmatically.
  silent,

  /// Forward response to a user-provided custom callback.
  custom,
}

/// Exception thrown by [RaspShield] when running in [SecurityMode.strict]
/// and a threat is detected.
class SecurityException implements Exception {
  /// Creates a [SecurityException] with the given [message].
  const SecurityException(this.message);

  /// Description of the security threat that was detected.
  final String message;

  @override
  String toString() => 'SecurityException: $message';
}
