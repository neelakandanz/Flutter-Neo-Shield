/// Configuration for the Clipboard Shield module.
library;

import 'clipboard_copy_result.dart';

/// Configuration for the [ClipboardShield] module.
///
/// Controls clipboard auto-clear behavior, PII detection on copy,
/// and callback hooks.
///
/// ```dart
/// final config = ClipboardShieldConfig(
///   defaultExpiry: Duration(seconds: 15),
///   clearAfterPaste: true,
///   detectPIIOnCopy: true,
/// );
/// ```
class ClipboardShieldConfig {
  /// Creates a [ClipboardShieldConfig] with the specified options.
  const ClipboardShieldConfig({
    this.defaultExpiry = const Duration(seconds: 30),
    this.clearAfterPaste = true,
    this.detectPIIOnCopy = true,
    this.logCopyEvents = false,
    this.onCopyCallback,
    this.onClearCallback,
  });

  /// Default duration after which the clipboard is auto-cleared.
  ///
  /// **Limitations:** The timer runs inside the Dart isolate. If the app
  /// is killed or force-stopped before the timer fires, the clipboard is
  /// NOT cleared. System clipboard history apps (Gboard, Samsung Keyboard,
  /// etc.) may also retain a copy independently of this timer.
  ///
  /// Set to [Duration.zero] to disable auto-clear.
  final Duration defaultExpiry;

  /// Whether to clear the clipboard immediately after a paste is detected.
  final bool clearAfterPaste;

  /// Whether to run PII detection on copied text.
  final bool detectPIIOnCopy;

  /// Whether to log copy events via LogShield (sanitized).
  final bool logCopyEvents;

  /// Optional callback invoked after each copy operation.
  final void Function(ClipboardCopyResult)? onCopyCallback;

  /// Optional callback invoked when the clipboard is auto-cleared.
  final void Function()? onClearCallback;
}
