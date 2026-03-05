/// Configuration for the Log Shield module.
library;

/// Configuration for the [LogShield] module.
///
/// Controls log output behavior including release mode suppression,
/// redaction notices, and custom output handlers.
///
/// ```dart
/// final config = LogShieldConfig(
///   silentInRelease: true,
///   showRedactionNotice: true,
///   outputHandler: (message, level) => myLogger.log(message),
/// );
/// ```
class LogShieldConfig {
  /// Creates a [LogShieldConfig] with the specified options.
  const LogShieldConfig({
    this.sanitizeInDebug = true,
    this.silentInRelease = true,
    this.silentInProfile = false,
    this.showRedactionNotice = false,
    this.outputHandler,
    this.showTimestamp = false,
    this.enabledLevels = const {},
  });

  /// Whether to sanitize (hide PII) in debug mode.
  ///
  /// - `true` (default): PII is hidden in all modes including debug.
  ///   This is the safe default — screenshots, screen recordings, CI
  ///   logs, and shared consoles will not contain real PII.
  /// - `false`: During development, `shieldLog()` shows all real values
  ///   for easy debugging. Only set this when you need to see raw data
  ///   locally and understand the risk.
  ///
  /// In **release mode**, logs are always sanitized (or silenced if
  /// [silentInRelease] is true). This flag only affects debug/development.
  final bool sanitizeInDebug;

  /// If true, suppress all log output in release mode.
  final bool silentInRelease;

  /// If true, suppress all log output in profile mode.
  final bool silentInProfile;

  /// If true, appends a redaction notice showing how many items were redacted.
  final bool showRedactionNotice;

  /// Optional callback to route sanitized logs to a custom logger.
  ///
  /// When set, sanitized messages are passed to this function instead
  /// of being printed to the console.
  ///
  /// ```dart
  /// outputHandler: (message, level) {
  ///   myLogger.log(level, message);
  /// },
  /// ```
  final void Function(String sanitizedMessage, String level)? outputHandler;

  /// Whether to prepend a timestamp to each log line.
  ///
  /// When true, each log line is prefixed with the current time in
  /// ISO 8601 format.
  final bool showTimestamp;

  /// Set of log levels to output. Empty set means all levels are enabled.
  ///
  /// ```dart
  /// enabledLevels: {'INFO', 'ERROR', 'WARNING'},
  /// ```
  final Set<String> enabledLevels;

  /// Returns whether the given [level] is enabled.
  bool isLevelEnabled(String level) =>
      enabledLevels.isEmpty || enabledLevels.contains(level.toUpperCase());
}
