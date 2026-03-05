/// Drop-in SecureCopyButton widget for clipboard protection.
library;

import 'dart:async';

import 'package:flutter/material.dart';

import 'clipboard_copy_result.dart';
import 'clipboard_shield.dart';

/// A widget that copies text securely to the clipboard on tap.
///
/// Optionally shows a snackbar with countdown and auto-clear notification.
///
/// ```dart
/// SecureCopyButton(
///   text: 'my-secret-api-key',
///   expireAfter: Duration(seconds: 15),
///   child: Icon(Icons.copy),
///   onCopied: () => print('Copied!'),
/// )
/// ```
class SecureCopyButton extends StatefulWidget {
  /// Creates a [SecureCopyButton] with the required [text] and [child].
  const SecureCopyButton({
    required this.text,
    required this.child,
    super.key,
    this.expireAfter,
    this.onCopied,
    this.onCleared,
    this.showSnackBar = true,
    this.snackBarDuration = const Duration(seconds: 2),
    this.copiedMessage,
    this.clearedMessage = 'Clipboard cleared',
    this.feedbackBuilder,
  });

  /// The text to copy to the clipboard.
  final String text;

  /// The child widget displayed as the button content.
  final Widget child;

  /// Optional duration override for auto-clear.
  final Duration? expireAfter;

  /// Called after a successful copy.
  final VoidCallback? onCopied;

  /// Called when the auto-clear timer fires.
  final VoidCallback? onCleared;

  /// Whether to show a snackbar after copying.
  final bool showSnackBar;

  /// Duration to display the snackbar.
  final Duration snackBarDuration;

  /// Custom copied message. Use `{seconds}` as placeholder for the timer.
  ///
  /// Defaults to "Copied! Auto-clearing in Xs" where X is the expiry seconds.
  final String? copiedMessage;

  /// Message shown when the clipboard is cleared.
  final String clearedMessage;

  /// Optional custom feedback builder instead of the default snackbar.
  final Widget Function(BuildContext, ClipboardCopyResult)? feedbackBuilder;

  @override
  State<SecureCopyButton> createState() => _SecureCopyButtonState();
}

class _SecureCopyButtonState extends State<SecureCopyButton> {
  StreamSubscription<void>? _clearSubscription;

  @override
  void dispose() {
    _clearSubscription?.cancel();
    super.dispose();
  }

  Future<void> _handleTap() async {
    final result = await ClipboardShield().copy(
      widget.text,
      expireAfter: widget.expireAfter,
    );

    if (!mounted) return;

    widget.onCopied?.call();

    // Listen for clear event.
    unawaited(_clearSubscription?.cancel());
    _clearSubscription = ClipboardShield().onCleared.listen((_) {
      if (!mounted) return;
      widget.onCleared?.call();

      if (widget.showSnackBar) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(widget.clearedMessage),
            duration: widget.snackBarDuration,
          ),
        );
      }
    });

    if (widget.feedbackBuilder != null) {
      // Show custom feedback.
      final overlay = Overlay.of(context);
      final entry = OverlayEntry(
        builder: (ctx) => widget.feedbackBuilder!(ctx, result),
      );
      overlay.insert(entry);
      await Future<void>.delayed(widget.snackBarDuration);
      if (mounted) {
        entry.remove();
      }
    } else if (widget.showSnackBar) {
      final expiry =
          widget.expireAfter ?? ClipboardShield().config.defaultExpiry;
      final seconds = expiry.inSeconds;
      final message =
          widget.copiedMessage ?? 'Copied! Auto-clearing in ${seconds}s';

      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(message),
          duration: widget.snackBarDuration,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: _handleTap,
      child: widget.child,
    );
  }
}
