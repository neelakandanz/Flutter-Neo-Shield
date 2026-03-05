/// PII type definitions and match result model for flutter_neo_shield.
library;

/// Enum representing the types of Personally Identifiable Information (PII)
/// that the detection engine can recognize.
///
/// Each type corresponds to a built-in or custom detection pattern.
///
/// ```dart
/// final type = PIIType.email;
/// print(type.displayName); // 'Email'
/// ```
enum PIIType {
  /// Email addresses (e.g., john@example.com).
  email,

  /// Phone numbers in various international formats.
  phone,

  /// US Social Security Numbers (e.g., 123-45-6789).
  ssn,

  /// Credit/debit card numbers (13-19 digits, Luhn-validated).
  creditCard,

  /// Date of birth patterns (YYYY-MM-DD, MM/DD/YYYY).
  dateOfBirth,

  /// IPv4 addresses (e.g., 192.168.1.1).
  ipAddress,

  /// JSON Web Tokens (eyJ... format).
  jwtToken,

  /// Bearer authorization tokens.
  bearerToken,

  /// Password and secret key-value pairs.
  passwordField,

  /// Common API key formats (sk-, pk-, api-, etc.).
  apiKey,

  /// International Bank Account Numbers (IBAN).
  iban,

  /// UK National Insurance Numbers (e.g., AB 12 34 56 C).
  ukNin,

  /// Canadian Social Insurance Numbers (e.g., 123-456-789).
  canadianSin,

  /// Passport numbers (common formats).
  passport,

  /// Dynamically registered person names.
  name,

  /// Custom user-defined patterns.
  custom;

  /// Returns a human-readable display name for this PII type.
  ///
  /// ```dart
  /// PIIType.creditCard.displayName; // 'Credit Card'
  /// ```
  String get displayName {
    switch (this) {
      case PIIType.email:
        return 'Email';
      case PIIType.phone:
        return 'Phone';
      case PIIType.ssn:
        return 'SSN';
      case PIIType.creditCard:
        return 'Credit Card';
      case PIIType.dateOfBirth:
        return 'Date of Birth';
      case PIIType.ipAddress:
        return 'IP Address';
      case PIIType.jwtToken:
        return 'JWT Token';
      case PIIType.bearerToken:
        return 'Bearer Token';
      case PIIType.passwordField:
        return 'Password Field';
      case PIIType.apiKey:
        return 'API Key';
      case PIIType.iban:
        return 'IBAN';
      case PIIType.ukNin:
        return 'UK NI Number';
      case PIIType.canadianSin:
        return 'Canadian SIN';
      case PIIType.passport:
        return 'Passport';
      case PIIType.name:
        return 'Name';
      case PIIType.custom:
        return 'Custom';
    }
  }
}

/// Represents a single PII match found within a string.
///
/// Contains the matched text, its position, the detected type, and
/// the replacement text that will be substituted.
///
/// ```dart
/// final matches = PIIDetector().detect('Email: john@test.com');
/// for (final match in matches) {
///   print('${match.type}: ${match.replacement}');
/// }
/// ```
class PIIMatch {
  /// Creates a [PIIMatch] with the given details.
  const PIIMatch({
    required this.type,
    required this.original,
    required this.start,
    required this.end,
    required this.replacement,
  });

  /// The type of PII detected.
  final PIIType type;

  /// The original matched text.
  final String original;

  /// The start index of the match in the source string.
  final int start;

  /// The end index of the match in the source string.
  final int end;

  /// The replacement text that will be substituted for the match.
  final String replacement;

  /// Returns a string representation without exposing [original].
  ///
  /// The original matched text is intentionally omitted to prevent
  /// accidental PII leaks when logging or printing match results.
  @override
  String toString() =>
      'PIIMatch(type: $type, start: $start, end: $end, replacement: $replacement)';

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PIIMatch &&
          runtimeType == other.runtimeType &&
          type == other.type &&
          original == other.original &&
          start == other.start &&
          end == other.end &&
          replacement == other.replacement;

  @override
  int get hashCode =>
      type.hashCode ^
      original.hashCode ^
      start.hashCode ^
      end.hashCode ^
      replacement.hashCode;
}
