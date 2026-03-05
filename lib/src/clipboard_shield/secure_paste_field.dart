/// TextField wrapper that auto-clears clipboard after paste.
library;

import 'package:flutter/material.dart';

import 'clipboard_shield.dart';

/// A [TextField] wrapper that automatically clears the clipboard after paste.
///
/// Detects paste actions by monitoring text changes and clears the
/// system clipboard when a paste is detected.
///
/// ```dart
/// SecurePasteField(
///   decoration: InputDecoration(labelText: 'Paste password here'),
///   clearAfterPaste: true,
///   onPasted: (text) => print('Pasted: $text'),
/// )
/// ```
class SecurePasteField extends StatefulWidget {
  /// Creates a [SecurePasteField] with optional configuration.
  const SecurePasteField({
    super.key,
    this.controller,
    this.decoration,
    this.clearAfterPaste = true,
    this.onPasted,
    this.keyboardType,
    this.obscureText = false,
    this.validator,
    this.onChanged,
    this.maxLines = 1,
    this.minLines,
    this.enabled,
    this.readOnly = false,
    this.autofocus = false,
    this.style,
  });

  /// Optional text editing controller.
  final TextEditingController? controller;

  /// Input decoration for the text field.
  final InputDecoration? decoration;

  /// Whether to clear the clipboard after a paste is detected.
  final bool clearAfterPaste;

  /// Callback invoked with the pasted text after a paste is detected.
  final void Function(String pastedText)? onPasted;

  /// The type of keyboard to use for editing the text.
  final TextInputType? keyboardType;

  /// Whether to obscure the text being edited.
  final bool obscureText;

  /// Optional form field validator.
  final String? Function(String?)? validator;

  /// Called when the text field value changes.
  final void Function(String)? onChanged;

  /// Maximum number of lines for the text field.
  final int? maxLines;

  /// Minimum number of lines for the text field.
  final int? minLines;

  /// Whether the text field is enabled.
  final bool? enabled;

  /// Whether the text field is read-only.
  final bool readOnly;

  /// Whether the text field should auto-focus.
  final bool autofocus;

  /// The style to use for the text being edited.
  final TextStyle? style;

  @override
  State<SecurePasteField> createState() => _SecurePasteFieldState();
}

class _SecurePasteFieldState extends State<SecurePasteField> {
  late TextEditingController _controller;
  String _previousText = '';

  @override
  void initState() {
    super.initState();
    _controller = widget.controller ?? TextEditingController();
    _previousText = _controller.text;
  }

  @override
  void dispose() {
    if (widget.controller == null) {
      _controller.dispose();
    }
    super.dispose();
  }

  void _onChanged(String newText) {
    // Detect paste by checking if multiple characters were added at once
    // and the new text doesn't start with the old text (insertion, not append).
    // Threshold of 3 chars reduces false positives from autocorrect/IME.
    final lengthDiff = newText.length - _previousText.length;
    if (lengthDiff >= 3) {
      // Determine the inserted segment.
      // If the old text is a prefix, the paste is at the end.
      // Otherwise, find the divergence point.
      String pastedText;
      if (newText.startsWith(_previousText)) {
        pastedText = newText.substring(_previousText.length);
      } else {
        pastedText = newText;
      }

      if (widget.clearAfterPaste) {
        // Await the clear to reduce the race window.
        ClipboardShield().clearNow();
      }

      widget.onPasted?.call(pastedText);
    }

    _previousText = newText;
    widget.onChanged?.call(newText);
  }

  @override
  Widget build(BuildContext context) {
    if (widget.validator != null) {
      return TextFormField(
        controller: _controller,
        decoration: widget.decoration,
        keyboardType: widget.keyboardType,
        obscureText: widget.obscureText,
        validator: widget.validator,
        onChanged: _onChanged,
        maxLines: widget.maxLines,
        minLines: widget.minLines,
        enabled: widget.enabled,
        readOnly: widget.readOnly,
        autofocus: widget.autofocus,
        style: widget.style,
      );
    }

    return TextField(
      controller: _controller,
      decoration: widget.decoration,
      keyboardType: widget.keyboardType,
      obscureText: widget.obscureText,
      onChanged: _onChanged,
      maxLines: widget.maxLines,
      minLines: widget.minLines,
      enabled: widget.enabled,
      readOnly: widget.readOnly,
      autofocus: widget.autofocus,
      style: widget.style,
    );
  }
}
