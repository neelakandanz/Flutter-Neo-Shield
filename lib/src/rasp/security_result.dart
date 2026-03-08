/// Result of a single security detection check
class SecurityResult {
  /// Constructs a new [SecurityResult] instance
  const SecurityResult({
    required this.isDetected,
    this.message,
    this.additionalData,
  });

  /// Indicates whether the security threat was detected
  final bool isDetected;

  /// Optional message detailing the detection reason
  final String? message;

  /// Optional key-value pairs with raw detection metrics
  final Map<String, dynamic>? additionalData;

  @override
  String toString() {
    return 'SecurityResult(isDetected: $isDetected, message: $message, additionalData: $additionalData)';
  }
}

/// Consolidated report of a full security scan
class SecurityReport {
  /// Constructs a [SecurityReport] from individual check results
  const SecurityReport({
    required this.debuggerDetected,
    required this.rootDetected,
    required this.emulatorDetected,
    required this.fridaDetected,
    required this.hookDetected,
    required this.integrityTampered,
    this.developerModeDetected = false,
  });

  /// True if a debugger is attached
  final bool debuggerDetected;

  /// True if device root (Android) or jailbreak (iOS) is detected
  final bool rootDetected;

  /// True if device is determined to be an emulator or simulator
  final bool emulatorDetected;

  /// True if Frida instrumentation is detected
  final bool fridaDetected;

  /// True if hooking frameworks (Xposed, Substrate, etc.) are detected
  final bool hookDetected;

  /// True if the app source or binary signature appears tampered
  final bool integrityTampered;

  /// True if Developer Options (Android) or Developer Mode (iOS 16+) is enabled
  final bool developerModeDetected;

  /// Represents the complete safety state. Returns true if NO threats are detected.
  bool get isSafe =>
      !debuggerDetected &&
      !rootDetected &&
      !emulatorDetected &&
      !fridaDetected &&
      !hookDetected &&
      !integrityTampered &&
      !developerModeDetected;

  @override
  String toString() {
    return 'SecurityReport(safe: $isSafe, debugger: $debuggerDetected, root: $rootDetected, emulator: $emulatorDetected, frida: $fridaDetected, hooks: $hookDetected, integrity: $integrityTampered, developerMode: $developerModeDetected)';
  }
}
