/// Main PII detection engine for flutter_neo_shield.
library;

import 'package:meta/meta.dart';

import 'pii_pattern.dart';
import 'pii_type.dart';
import 'shield_config.dart';
import 'shield_report.dart';

/// The core PII detection and sanitization engine.
///
/// Singleton class that detects and replaces Personally Identifiable
/// Information in strings using regex patterns and optional validators.
///
/// ```dart
/// final detector = PIIDetector();
/// final clean = detector.sanitize('Email: john@test.com');
/// print(clean); // 'Email: [EMAIL HIDDEN]'
/// ```
class PIIDetector {
  /// Returns the singleton [PIIDetector] instance.
  factory PIIDetector() => _instance;

  PIIDetector._internal() {
    _initBuiltInPatterns();
  }

  static final PIIDetector _instance = PIIDetector._internal();

  ShieldConfig _config = const ShieldConfig();
  ShieldReport? _report;
  final List<PIIPattern> _patterns = [];
  final Set<String> _sensitiveNames = {};
  final Map<String, RegExp> _nameRegexCache = {};

  // Cached regex constants for validators.
  static final RegExp _nonDigitRegex = RegExp(r'[^\d]');
  static final RegExp _phoneSeparatorRegex = RegExp(r'[+\-()\s.]');
  static final RegExp _cardSeparatorRegex = RegExp(r'[\s-]');
  static final RegExp _allDigitsRegex = RegExp(r'^\d+$');

  static const int _maxSanitizeDepth = 50;

  /// The default sensitive keys used for JSON sanitization.
  ///
  /// Keys are matched case-insensitively against JSON map keys.
  /// Add additional keys via [sanitizeJson]'s `sensitiveKeys` parameter
  /// or by configuring [ShieldConfig.customPatterns].
  static const List<String> defaultSensitiveKeys = [
    // Identity
    'name',
    'username',
    'user_name',
    'first_name',
    'firstName',
    'last_name',
    'lastName',
    'full_name',
    'fullName',
    'email',
    'phone',
    'phone_number',
    'phoneNumber',
    'ssn',
    'social_security',
    'dob',
    'date_of_birth',
    'dateOfBirth',
    'birthDate',
    'birth_date',
    // Address
    'address',
    'street',
    'zip',
    'postal_code',
    'postalCode',
    // Auth & secrets
    'password',
    'passwd',
    'pwd',
    'pass',
    'pin',
    'token',
    'secret',
    'access_token',
    'accessToken',
    'refresh_token',
    'refreshToken',
    'api_key',
    'apiKey',
    'api_secret',
    'apiSecret',
    'private_key',
    'privateKey',
    'authorization',
    'auth',
    'bearer',
    'session',
    'session_id',
    'sessionId',
    'cookie',
    // Financial
    'creditCard',
    'credit_card',
    'cardNumber',
    'card_number',
    'cvv',
    'cvc',
    'account',
    'account_number',
    'accountNumber',
    'routing',
    'routing_number',
    'routingNumber',
    'iban',
    // Medical / telecom
    'telecom',
    'identifier',
  ];

  /// Configures the detector with the given [config].
  ///
  /// Can be called multiple times to update configuration.
  ///
  /// ```dart
  /// PIIDetector().configure(ShieldConfig(
  ///   enabledTypes: {PIIType.email, PIIType.phone},
  ///   enableReporting: true,
  /// ));
  /// ```
  void configure(ShieldConfig config) {
    _config = config;
    if (config.enableReporting) {
      _report ??= ShieldReport();
    }

    // Clear and re-register sensitive names to prevent accumulation.
    _sensitiveNames.clear();
    _nameRegexCache.clear();
    for (final name in config.sensitiveNames) {
      _sensitiveNames.add(name);
    }

    // Add custom patterns.
    for (final pattern in config.customPatterns) {
      if (!_patterns.any(
        (p) =>
            p.type == pattern.type && p.regex.pattern == pattern.regex.pattern,
      )) {
        _patterns.add(pattern);
      }
    }
  }

  /// The current configuration.
  ShieldConfig get config => _config;

  /// The detection report, or null if reporting is disabled.
  ShieldReport? get report => _report;

  /// Registers a single sensitive [name] for name detection.
  ///
  /// Names must be at least 3 characters to avoid false positives
  /// with common English words (e.g., "Al", "Jo", "Ed").
  ///
  /// ```dart
  /// PIIDetector().registerName('John');
  /// ```
  void registerName(String name) {
    if (name.length >= 3) {
      _sensitiveNames.add(name);
    }
  }

  /// Registers multiple sensitive [names] at once.
  ///
  /// ```dart
  /// PIIDetector().registerNames(['John', 'Doe', 'Maria']);
  /// ```
  void registerNames(List<String> names) {
    for (final name in names) {
      registerName(name);
    }
  }

  /// Removes a previously registered [name].
  ///
  /// ```dart
  /// PIIDetector().unregisterName('John');
  /// ```
  void unregisterName(String name) {
    _sensitiveNames.remove(name);
  }

  /// Clears all registered sensitive names.
  ///
  /// Useful to call on user logout.
  ///
  /// ```dart
  /// PIIDetector().clearNames();
  /// ```
  void clearNames() {
    _sensitiveNames.clear();
    _nameRegexCache.clear();
  }

  /// Returns the set of currently registered sensitive names.
  @visibleForTesting
  Set<String> get sensitiveNames => Set.unmodifiable(_sensitiveNames);

  /// Adds a custom [PIIPattern] at runtime.
  ///
  /// Duplicate patterns (same type and regex) are silently ignored.
  ///
  /// ```dart
  /// PIIDetector().addPattern(PIIPattern(
  ///   type: PIIType.custom,
  ///   regex: RegExp(r'ACCT-\d{10}'),
  ///   replacement: '[ACCOUNT HIDDEN]',
  /// ));
  /// ```
  void addPattern(PIIPattern pattern) {
    final isDuplicate = _patterns.any(
      (p) => p.type == pattern.type && p.regex.pattern == pattern.regex.pattern,
    );
    if (!isDuplicate) {
      _patterns.add(pattern);
    }
  }

  /// Removes all patterns of the given [type].
  ///
  /// ```dart
  /// PIIDetector().removePattern(PIIType.email);
  /// ```
  void removePattern(PIIType type) {
    _patterns.removeWhere((p) => p.type == type);
  }

  /// The main sanitization method. Replaces all detected PII in [input]
  /// with configured replacement text.
  ///
  /// ```dart
  /// final clean = PIIDetector().sanitize('Call 555-123-4567');
  /// print(clean); // 'Call [PHONE HIDDEN]'
  /// ```
  String sanitize(String input) {
    if (input.isEmpty) return input;

    final matches = detect(input);
    if (matches.isEmpty) return input;

    // Sort matches by start position descending so replacements don't
    // shift indices for earlier matches.
    final sorted = List<PIIMatch>.from(matches)
      ..sort((a, b) => b.start.compareTo(a.start));

    var result = input;
    for (final match in sorted) {
      result = result.replaceRange(match.start, match.end, match.replacement);
    }

    return result;
  }

  /// Detects all PII in [input] and returns a list of [PIIMatch] objects.
  ///
  /// Does not modify the input string.
  ///
  /// ```dart
  /// final matches = PIIDetector().detect('Email: john@test.com');
  /// print(matches.length); // 1
  /// print(matches.first.type); // PIIType.email
  /// ```
  List<PIIMatch> detect(String input) {
    if (input.isEmpty) return [];

    final allMatches = <_PrioritizedMatch>[];

    for (var priority = 0; priority < _patterns.length; priority++) {
      final pattern = _patterns[priority];
      if (!_config.isTypeEnabled(pattern.type)) continue;

      final regexMatches = pattern.regex.allMatches(input);
      for (final regexMatch in regexMatches) {
        final matched = regexMatch.group(0)!;

        // Run optional validator.
        if (pattern.validator != null && !pattern.validator!(matched)) {
          continue;
        }

        final replacement =
            _config.customReplacements[pattern.type] ?? pattern.replacement;

        // For password fields, preserve the key name.
        String finalReplacement;
        if (pattern.type == PIIType.passwordField) {
          final keyMatch = RegExp(
            r'(password|passwd|pwd|secret|token|api_key|apikey|api-key|access_token|refresh_token)',
            caseSensitive: false,
          ).firstMatch(matched);
          if (keyMatch != null) {
            final key = keyMatch.group(0)!;
            final sepIndex = matched.indexOf(RegExp(r'[=:]'), keyMatch.end);
            if (sepIndex >= 0 && sepIndex < matched.length) {
              final endIdx = (sepIndex + 1).clamp(0, matched.length);
              final separator = matched.substring(keyMatch.end, endIdx);
              finalReplacement = '$key$separator[HIDDEN]';
            } else {
              finalReplacement = '$key=[HIDDEN]';
            }
          } else {
            finalReplacement = replacement;
          }
        } else {
          finalReplacement = replacement;
        }

        allMatches.add(_PrioritizedMatch(
          priority: priority,
          match: PIIMatch(
            type: pattern.type,
            original: matched,
            start: regexMatch.start,
            end: regexMatch.end,
            replacement: finalReplacement,
          ),
        ));

        if (_config.enableReporting) {
          _report?.recordDetection(pattern.type);
        }
      }
    }

    // Handle registered names (PIIType.name).
    if (_config.isTypeEnabled(PIIType.name) && _sensitiveNames.isNotEmpty) {
      final namePriority = _patterns.length; // Lowest priority.
      for (final name in _sensitiveNames) {
        if (name.length < 3) continue;

        final nameRegex = _nameRegexCache.putIfAbsent(
          name.toLowerCase(),
          () => RegExp('\\b${RegExp.escape(name)}\\b', caseSensitive: false),
        );
        final nameMatches = nameRegex.allMatches(input);
        for (final match in nameMatches) {
          final replacement =
              _config.customReplacements[PIIType.name] ?? '[NAME HIDDEN]';

          // Check for overlap with existing matches.
          final overlaps = allMatches.any(
            (m) => match.start < m.match.end && match.end > m.match.start,
          );
          if (!overlaps) {
            allMatches.add(_PrioritizedMatch(
              priority: namePriority,
              match: PIIMatch(
                type: PIIType.name,
                original: match.group(0)!,
                start: match.start,
                end: match.end,
                replacement: replacement,
              ),
            ));

            if (_config.enableReporting) {
              _report?.recordDetection(PIIType.name);
            }
          }
        }
      }
    }

    // Remove overlapping matches — when overlaps occur, keep the higher
    // priority (lower number) pattern. Sort by priority first to process
    // more important patterns first.
    allMatches.sort((a, b) => a.priority.compareTo(b.priority));

    final deduped = <PIIMatch>[];
    for (final pm in allMatches) {
      // Check if this match overlaps with any already-selected match.
      final overlaps = deduped.any(
        (m) => pm.match.start < m.end && pm.match.end > m.start,
      );
      if (!overlaps) {
        deduped.add(pm.match);
      }
    }

    // Sort final results by position for correct replacement order.
    deduped.sort((a, b) => a.start.compareTo(b.start));

    return deduped;
  }

  /// Returns true if [input] contains any detectable PII.
  ///
  /// ```dart
  /// PIIDetector().containsPII('john@test.com'); // true
  /// PIIDetector().containsPII('Hello world'); // false
  /// ```
  bool containsPII(String input) => detect(input).isNotEmpty;

  /// Returns the [PIIType] of the first PII found in [input], or null.
  ///
  /// ```dart
  /// PIIDetector().getPIIType('john@test.com'); // PIIType.email
  /// ```
  PIIType? getPIIType(String input) {
    final matches = detect(input);
    return matches.isEmpty ? null : matches.first.type;
  }

  /// Sanitizes a JSON map by replacing values of sensitive keys with
  /// `[REDACTED]` and running PII detection on remaining string values.
  ///
  /// Recursively processes nested maps and lists.
  ///
  /// ```dart
  /// final clean = PIIDetector().sanitizeJson({
  ///   'name': 'John',
  ///   'id': 123,
  ///   'note': 'Call 555-123-4567',
  /// });
  /// // {'name': '[REDACTED]', 'id': 123, 'note': 'Call [PHONE HIDDEN]'}
  /// ```
  Map<String, dynamic> sanitizeJson(
    Map<String, dynamic> json, {
    List<String>? sensitiveKeys,
  }) {
    final keys = sensitiveKeys ?? defaultSensitiveKeys;
    final keysLower = keys.map((k) => k.toLowerCase()).toSet();

    return _sanitizeMap(json, keysLower, 0);
  }

  Map<String, dynamic> _sanitizeMap(
    Map<String, dynamic> json,
    Set<String> sensitiveKeysLower,
    int depth,
  ) {
    if (depth >= _maxSanitizeDepth) return json;
    final result = <String, dynamic>{};

    for (final entry in json.entries) {
      if (sensitiveKeysLower.contains(entry.key.toLowerCase())) {
        result[entry.key] = '[REDACTED]';
      } else if (entry.value is Map<String, dynamic>) {
        result[entry.key] = _sanitizeMap(
          entry.value as Map<String, dynamic>,
          sensitiveKeysLower,
          depth + 1,
        );
      } else if (entry.value is List) {
        result[entry.key] = _sanitizeList(
          entry.value as List<dynamic>,
          sensitiveKeysLower,
          depth + 1,
        );
      } else if (entry.value is String) {
        result[entry.key] = sanitize(entry.value as String);
      } else {
        result[entry.key] = entry.value;
      }
    }

    return result;
  }

  List<dynamic> _sanitizeList(
    List<dynamic> list,
    Set<String> sensitiveKeysLower,
    int depth,
  ) {
    if (depth >= _maxSanitizeDepth) return list;
    return list.map((item) {
      if (item is Map<String, dynamic>) {
        return _sanitizeMap(item, sensitiveKeysLower, depth + 1);
      } else if (item is List) {
        return _sanitizeList(item, sensitiveKeysLower, depth + 1);
      } else if (item is String) {
        return sanitize(item);
      }
      return item;
    }).toList();
  }

  /// Resets the detector to its default state.
  ///
  /// Clears all custom patterns, registered names, and report data.
  /// Useful in tests.
  ///
  /// ```dart
  /// PIIDetector().reset();
  /// ```
  void reset() {
    _config = const ShieldConfig();
    _report?.reset();
    _report = null;
    _sensitiveNames.clear();
    _nameRegexCache.clear();
    _patterns.clear();
    _initBuiltInPatterns();
  }

  /// Initializes the built-in PII detection patterns.
  ///
  /// Order matters: SSN before phone, JWT before generic API key,
  /// password fields before generic strings.
  void _initBuiltInPatterns() {
    _patterns.addAll([
      // 1. SSN — process BEFORE phone to avoid conflicts.
      PIIPattern(
        type: PIIType.ssn,
        regex: RegExp(r'\b\d{3}-\d{2}-\d{4}\b'),
        replacement: '[SSN HIDDEN]',
        description: 'US Social Security Numbers with dashes',
        validator: _ssnDashedValidate,
      ),
      PIIPattern(
        type: PIIType.ssn,
        regex: RegExp(r'\b(?<!\d)\d{9}(?!\d)\b'),
        replacement: '[SSN HIDDEN]',
        description:
            'US Social Security Numbers without dashes (9 consecutive digits)',
        validator: _ssnNoDashValidate,
      ),

      // 2. Credit Card — Luhn-validated.
      PIIPattern(
        type: PIIType.creditCard,
        regex: RegExp(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b'),
        replacement: '[CARD HIDDEN]',
        description: 'Credit/debit card numbers (13-19 digits)',
        validator: _luhnValidate,
      ),

      // 3. JWT Token.
      PIIPattern(
        type: PIIType.jwtToken,
        regex: RegExp(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
        replacement: '[JWT HIDDEN]',
        description: 'JSON Web Tokens',
      ),

      // 4. Bearer Token — require token-like content (min 8 chars, alphanumeric/symbols).
      PIIPattern(
        type: PIIType.bearerToken,
        regex: RegExp(r'Bearer\s+[A-Za-z0-9_\-./+=]{8,}', caseSensitive: false),
        replacement: 'Bearer [TOKEN HIDDEN]',
        description: 'Authorization bearer tokens',
      ),

      // 5. Password fields — key-value pairs with sensitive keys.
      PIIPattern(
        type: PIIType.passwordField,
        regex: RegExp(
          r'(password|passwd|pwd|secret|token|api_key|apikey|api-key|access_token|refresh_token)\s*[=:]\s*\S+',
          caseSensitive: false,
        ),
        replacement: '[PASSWORD HIDDEN]',
        description: 'Password and secret key-value pairs',
      ),

      // 6. API Key — common prefixed formats requiring at least one digit.
      PIIPattern(
        type: PIIType.apiKey,
        regex: RegExp(
            r'\b(?:sk|pk|api|key|token)[_-][A-Za-z0-9_-]*\d[A-Za-z0-9_-]*\b'),
        replacement: '[API_KEY HIDDEN]',
        description: 'Common API key formats',
        validator: _apiKeyValidate,
      ),

      // 7. Email addresses — disallows consecutive dots per RFC 5322.
      PIIPattern(
        type: PIIType.email,
        regex: RegExp(
          r'\b[A-Za-z0-9](?:[A-Za-z0-9._%+-]*[A-Za-z0-9])?@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}\b',
        ),
        replacement: '[EMAIL HIDDEN]',
        description: 'Email addresses',
      ),

      // 8. Date of Birth — process BEFORE phone to avoid conflicts.
      PIIPattern(
        type: PIIType.dateOfBirth,
        regex: RegExp(
          r'\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b',
        ),
        replacement: '[DOB HIDDEN]',
        description: 'Dates in YYYY-MM-DD format',
      ),
      PIIPattern(
        type: PIIType.dateOfBirth,
        regex: RegExp(
          r'\b(?:0[1-9]|1[0-2])[/](?:0[1-9]|[12]\d|3[01])[/](?:19|20)\d{2}\b',
        ),
        replacement: '[DOB HIDDEN]',
        description: 'Dates in MM/DD/YYYY format',
      ),
      // DD/MM/YYYY (European format).
      PIIPattern(
        type: PIIType.dateOfBirth,
        regex: RegExp(
          r'\b(?:0[1-9]|[12]\d|3[01])[/](?:0[1-9]|1[0-2])[/](?:19|20)\d{2}\b',
        ),
        replacement: '[DOB HIDDEN]',
        description: 'Dates in DD/MM/YYYY format (European)',
      ),

      // 9a. IP Address (IPv4) — process BEFORE phone to avoid conflicts.
      PIIPattern(
        type: PIIType.ipAddress,
        regex: RegExp(
          r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
        ),
        replacement: '[IP HIDDEN]',
        description: 'IPv4 addresses',
      ),
      // 9b. IP Address (IPv6) — abbreviated and full forms.
      PIIPattern(
        type: PIIType.ipAddress,
        regex: RegExp(
          r'(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4})',
        ),
        replacement: '[IP HIDDEN]',
        description: 'IPv6 addresses',
      ),

      // 10. IBAN — international bank account numbers.
      PIIPattern(
        type: PIIType.iban,
        regex: RegExp(
          r'\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}[\s]?(?:[\dA-Z]{4}[\s]?){1,7}[\dA-Z]{1,4}\b',
        ),
        replacement: '[IBAN HIDDEN]',
        description: 'International Bank Account Numbers',
      ),

      // 11. UK National Insurance Number.
      PIIPattern(
        type: PIIType.ukNin,
        regex: RegExp(
          r'\b[A-CEGHJ-PR-TW-Z]{2}[\s-]?\d{2}[\s-]?\d{2}[\s-]?\d{2}[\s-]?[A-D]\b',
          caseSensitive: false,
        ),
        replacement: '[NI NUMBER HIDDEN]',
        description: 'UK National Insurance Numbers',
      ),

      // 12. Canadian Social Insurance Number.
      PIIPattern(
        type: PIIType.canadianSin,
        regex: RegExp(r'\b\d{3}[\s-]\d{3}[\s-]\d{3}\b'),
        replacement: '[SIN HIDDEN]',
        description: 'Canadian Social Insurance Numbers',
      ),

      // 13. Passport numbers (common formats: 1-2 letters + 6-9 digits).
      PIIPattern(
        type: PIIType.passport,
        regex: RegExp(r'\b[A-Z]{1,2}\d{6,9}\b'),
        replacement: '[PASSPORT HIDDEN]',
        description: 'Passport numbers',
      ),

      // 14. Phone numbers (international) — after IP to avoid matching IPs.
      PIIPattern(
        type: PIIType.phone,
        regex: RegExp(
          r'(?:\+\d{1,3}[\s-]?)(?:\(?\d{2,4}\)?[\s-]?)(?:\d[\s-]?){6,14}\d\b'
          r'|'
          r'\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b',
        ),
        replacement: '[PHONE HIDDEN]',
        description: 'Phone numbers in various international formats',
        validator: _phoneValidate,
      ),
    ]);
  }

  /// Validates a dashed SSN by checking area/group/serial rules.
  static bool _ssnDashedValidate(String match) {
    final parts = match.split('-');
    if (parts.length != 3) return false;
    final area = int.tryParse(parts[0]) ?? 0;
    final group = int.tryParse(parts[1]) ?? 0;
    final serial = int.tryParse(parts[2]) ?? 0;
    if (area == 0 || area == 666 || area >= 900) return false;
    if (group == 0 || serial == 0) return false;
    return true;
  }

  /// Validates a 9-digit SSN (no dashes) by checking area/group rules.
  ///
  /// Rejects known invalid SSN patterns: area 000/666/900-999.
  static bool _ssnNoDashValidate(String match) {
    if (match.length != 9) return false;
    final area = int.tryParse(match.substring(0, 3)) ?? 0;
    final group = int.tryParse(match.substring(3, 5)) ?? 0;
    final serial = int.tryParse(match.substring(5, 9)) ?? 0;
    // Invalid SSN area numbers per SSA rules.
    if (area == 0 || area == 666 || area >= 900) return false;
    if (group == 0 || serial == 0) return false;
    return true;
  }

  /// Validates a phone number match by checking digit count.
  ///
  /// Requires 7-15 digits (ITU-T E.164 range) and at least one
  /// separator or country code prefix to avoid matching plain numbers.
  static bool _phoneValidate(String match) {
    final digits = match.replaceAll(_nonDigitRegex, '');
    if (digits.length < 7 || digits.length > 15) return false;
    return match.contains(_phoneSeparatorRegex);
  }

  /// Validates an API key by ensuring minimum 8 chars after prefix separator.
  static bool _apiKeyValidate(String match) {
    final sepIndex = match.indexOf(RegExp(r'[_-]'));
    if (sepIndex < 0) return false;
    return match.length - sepIndex - 1 >= 8;
  }

  /// Validates a credit card number using the Luhn algorithm.
  static bool _luhnValidate(String match) {
    final digits = match.replaceAll(_cardSeparatorRegex, '');
    if (digits.length < 13 || digits.length > 19) return false;
    if (!_allDigitsRegex.hasMatch(digits)) return false;

    var sum = 0;
    var alternate = false;

    for (var i = digits.length - 1; i >= 0; i--) {
      var n = int.parse(digits[i]);
      if (alternate) {
        n *= 2;
        if (n > 9) n -= 9;
      }
      sum += n;
      alternate = !alternate;
    }

    return sum % 10 == 0;
  }
}

/// Internal helper to track pattern priority during detection.
class _PrioritizedMatch {
  const _PrioritizedMatch({required this.priority, required this.match});

  final int priority;
  final PIIMatch match;
}
