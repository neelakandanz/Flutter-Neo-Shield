import 'package:flutter_neo_shield/flutter_neo_shield.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  setUp(() {
    PIIDetector().reset();
  });

  group('PIIDetector', () {
    group('Email detection', () {
      test('sanitizes a single email address', () {
        final result = PIIDetector().sanitize('Contact john@example.com');
        expect(result, 'Contact [EMAIL HIDDEN]');
      });

      test('sanitizes multiple emails in one string', () {
        final result = PIIDetector().sanitize(
          'From alice@test.com to bob@example.org',
        );
        expect(result, contains('[EMAIL HIDDEN]'));
        expect(
          '[EMAIL HIDDEN]'.allMatches(result).length,
          2,
        );
        expect(result, isNot(contains('alice@test.com')));
        expect(result, isNot(contains('bob@example.org')));
      });
    });

    group('Phone detection', () {
      test('sanitizes US phone with country code and parens', () {
        final result = PIIDetector().sanitize('Call +1 (555) 123-4567');
        expect(result, contains('[PHONE HIDDEN]'));
        expect(result, isNot(contains('555')));
      });

      test('sanitizes US phone with dashes', () {
        final result = PIIDetector().sanitize('Call 555-123-4567');
        expect(result, contains('[PHONE HIDDEN]'));
        expect(result, isNot(contains('555-123-4567')));
      });

      test('sanitizes international phone number', () {
        final result = PIIDetector().sanitize('Call +91 98765 43210');
        expect(result, contains('[PHONE HIDDEN]'));
        expect(result, isNot(contains('98765')));
      });
    });

    group('SSN detection', () {
      test('sanitizes SSN with dashes', () {
        final result = PIIDetector().sanitize('SSN: 123-45-6789');
        expect(result, 'SSN: [SSN HIDDEN]');
      });

      test('sanitizes SSN without dashes', () {
        final result = PIIDetector().sanitize('SSN: 123456789');
        expect(result, 'SSN: [SSN HIDDEN]');
      });
    });

    group('Credit card detection', () {
      test('sanitizes Luhn-valid credit card number', () {
        final result = PIIDetector().sanitize('Card: 4532015112830366');
        expect(result, 'Card: [CARD HIDDEN]');
      });

      test('sanitizes Luhn-valid credit card with spaces', () {
        final result = PIIDetector().sanitize('Card: 4532 0151 1283 0366');
        expect(result, 'Card: [CARD HIDDEN]');
      });

      test('does NOT flag Luhn-invalid 16 digit number', () {
        final result = PIIDetector().sanitize('Number: 1234567890123456');
        expect(result, isNot(contains('[CARD HIDDEN]')));
      });
    });

    group('JWT detection', () {
      test('sanitizes JWT token', () {
        const jwt =
            'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456';
        final result = PIIDetector().sanitize('Token: $jwt');
        expect(result, contains('[JWT HIDDEN]'));
        expect(result, isNot(contains('eyJhbGciOiJIUzI1NiJ9')));
      });
    });

    group('Bearer token detection', () {
      test('sanitizes bearer token', () {
        final result = PIIDetector().sanitize(
          'Authorization: Bearer abc123xyz',
        );
        expect(result, contains('Bearer [TOKEN HIDDEN]'));
        expect(result, isNot(contains('abc123xyz')));
      });
    });

    group('Password field detection', () {
      test('sanitizes password=value pattern', () {
        final result = PIIDetector().sanitize('password=secret123');
        expect(result, contains('[HIDDEN]'));
        expect(result, isNot(contains('secret123')));
      });

      test('sanitizes api_key: value pattern', () {
        final result = PIIDetector().sanitize('api_key: sk-12345');
        expect(result, contains('[HIDDEN]'));
        expect(result, isNot(contains('sk-12345')));
      });

      test('handles missing value safely (e.g., password= at end of string)',
          () {
        final result = PIIDetector().sanitize('password=');
        expect(result, 'password=');
      });
    });

    group('API key detection', () {
      test('sanitizes common API key formats', () {
        final result = PIIDetector().sanitize(
          'sk-abc123defghijklmnopqrstuvwxyz',
        );
        expect(result, '[API_KEY HIDDEN]');
      });
    });

    group('Date of birth detection', () {
      test('sanitizes YYYY-MM-DD format', () {
        final result = PIIDetector().sanitize('Born: 1985-03-15');
        expect(result, 'Born: [DOB HIDDEN]');
      });

      test('sanitizes MM/DD/YYYY format', () {
        final result = PIIDetector().sanitize('Born: 03/15/1985');
        expect(result, 'Born: [DOB HIDDEN]');
      });
    });

    group('IP address detection', () {
      test('sanitizes IPv4 address', () {
        final result = PIIDetector().sanitize('Server: 192.168.1.1');
        expect(result, 'Server: [IP HIDDEN]');
      });
    });

    group('Name detection', () {
      test('sanitizes registered names', () {
        PIIDetector().registerName('John');
        PIIDetector().registerName('Doe');
        final result = PIIDetector().sanitize('Hello John Doe');
        expect(result, 'Hello [NAME HIDDEN] [NAME HIDDEN]');
      });

      test('matches short names with 3+ characters', () {
        PIIDetector().registerName('Joe');
        final result = PIIDetector().sanitize('Hello Joe');
        expect(result, contains('[NAME HIDDEN]'));
        expect(result, isNot(contains(' Joe')));
      });

      test('does NOT match 1-2 character names', () {
        PIIDetector().registerName('A');
        PIIDetector().registerName('Jo');
        final result = PIIDetector().sanitize('Hello A and Jo friend');
        expect(result, contains(' A '));
        expect(result, contains(' Jo '));
      });
    });

    group('Multiple PII types in one string', () {
      test('sanitizes multiple different PII types', () {
        final result = PIIDetector().sanitize(
          'Email john@test.com from 192.168.1.1',
        );
        expect(result, contains('[EMAIL HIDDEN]'));
        expect(result, contains('[IP HIDDEN]'));
        expect(result, isNot(contains('john@test.com')));
        expect(result, isNot(contains('192.168.1.1')));
      });
    });

    group('No PII', () {
      test('returns input unchanged when no PII present', () {
        final result = PIIDetector().sanitize('Hello world');
        expect(result, 'Hello world');
      });
    });

    group('Empty input', () {
      test('returns empty string for empty input', () {
        final result = PIIDetector().sanitize('');
        expect(result, '');
      });
    });

    group('Custom patterns', () {
      test('detects custom pattern added at runtime', () {
        PIIDetector().addPattern(PIIPattern(
          type: PIIType.custom,
          regex: RegExp(r'ACCT-\d{6}'),
          replacement: '[ACCOUNT HIDDEN]',
        ));
        final result = PIIDetector().sanitize('Account: ACCT-123456');
        expect(result, 'Account: [ACCOUNT HIDDEN]');
      });
    });

    group('Custom replacement', () {
      test('uses custom replacement text for email', () {
        PIIDetector().configure(const ShieldConfig(
          customReplacements: {PIIType.email: '[REMOVED]'},
        ));
        final result = PIIDetector().sanitize('Email: john@test.com');
        expect(result, 'Email: [REMOVED]');
      });
    });

    group('containsPII()', () {
      test('returns true when PII is present', () {
        expect(PIIDetector().containsPII('john@test.com'), isTrue);
      });

      test('returns false when no PII is present', () {
        expect(PIIDetector().containsPII('Hello world'), isFalse);
      });

      test('returns false for empty string', () {
        expect(PIIDetector().containsPII(''), isFalse);
      });
    });

    group('detect()', () {
      test('returns list of PIIMatch with correct type', () {
        final matches = PIIDetector().detect('Email: john@test.com');
        expect(matches, isNotEmpty);
        expect(matches.first.type, PIIType.email);
      });

      test('returns correct start and end positions', () {
        const input = 'Email: john@test.com';
        final matches = PIIDetector().detect(input);
        expect(matches, hasLength(1));
        final match = matches.first;
        expect(match.start, 7);
        expect(match.end, 20);
        expect(input.substring(match.start, match.end), 'john@test.com');
      });

      test('returns empty list when no PII is found', () {
        final matches = PIIDetector().detect('Hello world');
        expect(matches, isEmpty);
      });

      test('returns multiple matches for multiple PII instances', () {
        final matches = PIIDetector().detect(
          'Email john@test.com and IP 192.168.1.1',
        );
        expect(matches.length, greaterThanOrEqualTo(2));
        final types = matches.map((m) => m.type).toSet();
        expect(types, contains(PIIType.email));
        expect(types, contains(PIIType.ipAddress));
      });
    });

    group('sanitizeJson()', () {
      test('redacts sensitive keys', () {
        final result = PIIDetector().sanitizeJson({
          'name': 'John',
          'email': 'john@test.com',
        });
        expect(result['name'], '[REDACTED]');
        expect(result['email'], '[REDACTED]');
      });

      test('passes through non-sensitive keys', () {
        final result = PIIDetector().sanitizeJson({
          'id': 123,
          'status': 'active',
        });
        expect(result['id'], 123);
        expect(result['status'], 'active');
      });

      test('sanitizes nested maps', () {
        final result = PIIDetector().sanitizeJson({
          'user': {
            'name': 'John',
            'id': 42,
          },
        });
        final user = result['user'] as Map<String, dynamic>;
        expect(user['name'], '[REDACTED]');
        expect(user['id'], 42);
      });

      test('sanitizes PII in non-sensitive string values', () {
        final result = PIIDetector().sanitizeJson({
          'note': 'Contact john@example.com',
        });
        expect(result['note'], contains('[EMAIL HIDDEN]'));
        expect(result['note'], isNot(contains('john@example.com')));
      });

      test('returns empty map for empty input', () {
        final result = PIIDetector().sanitizeJson({});
        expect(result, isEmpty);
      });
    });

    group('clearNames()', () {
      test('removes all registered names', () {
        PIIDetector().registerNames(['John', 'Doe']);
        expect(PIIDetector().sensitiveNames, isNotEmpty);
        PIIDetector().clearNames();
        expect(PIIDetector().sensitiveNames, isEmpty);
      });

      test('names are no longer detected after clearing', () {
        PIIDetector().registerName('John');
        expect(PIIDetector().containsPII('Hello John'), isTrue);
        PIIDetector().clearNames();
        final result = PIIDetector().sanitize('Hello John');
        expect(result, 'Hello John');
      });
    });

    group('SSN dashed validation edge cases', () {
      test('rejects area 000', () {
        final result = PIIDetector().sanitize('SSN: 000-12-3456');
        expect(result, 'SSN: 000-12-3456'); // not detected
      });

      test('rejects area 666', () {
        final result = PIIDetector().sanitize('SSN: 666-12-3456');
        expect(result, 'SSN: 666-12-3456'); // not detected
      });

      test('rejects area 900+', () {
        final result = PIIDetector().sanitize('SSN: 900-12-3456');
        expect(result, 'SSN: 900-12-3456'); // not detected
      });

      test('rejects group 00', () {
        final result = PIIDetector().sanitize('SSN: 123-00-4567');
        expect(result, 'SSN: 123-00-4567'); // not detected
      });

      test('rejects serial 0000', () {
        final result = PIIDetector().sanitize('SSN: 123-45-0000');
        expect(result, 'SSN: 123-45-0000'); // not detected
      });

      test('accepts valid SSN', () {
        final result = PIIDetector().sanitize('SSN: 123-45-6789');
        expect(result, 'SSN: [SSN HIDDEN]');
      });
    });

    group('API key validation edge cases', () {
      test('rejects short API key (less than 8 chars after prefix)', () {
        final result = PIIDetector().sanitize('key: sk-ab1cd');
        expect(result, isNot(contains('[API_KEY HIDDEN]')));
      });

      test('rejects API key without digits', () {
        final result = PIIDetector().sanitize('sk-abcdefghijklmnop');
        expect(result, isNot(contains('[API_KEY HIDDEN]')));
      });

      test('accepts valid API key with digits and 8+ chars', () {
        final result = PIIDetector().sanitize('sk-abc123defghijk');
        expect(result, '[API_KEY HIDDEN]');
      });
    });

    group('Name detection', () {
      test('detects registered name with word boundaries', () {
        PIIDetector().registerName('Alice');
        final result = PIIDetector().sanitize('Hello Alice!');
        expect(result, 'Hello [NAME HIDDEN]!');
      });

      test('does not match partial word', () {
        PIIDetector().registerName('Alice');
        final result = PIIDetector().sanitize('Malice is bad');
        // "Alice" in "Malice" should not match (word boundary).
        expect(result, 'Malice is bad');
      });

      test('rejects names shorter than 3 chars', () {
        PIIDetector().registerName('Al');
        expect(PIIDetector().sensitiveNames, isEmpty);
      });
    });

    group('International PII patterns', () {
      test('detects IBAN', () {
        final result =
            PIIDetector().sanitize('IBAN: GB29 NWBK 6016 1331 9268 19');
        expect(result, contains('[IBAN HIDDEN]'));
      });

      test('detects UK NI number', () {
        final result = PIIDetector().sanitize('NI: AB 12 34 56 C');
        expect(result, contains('[NI NUMBER HIDDEN]'));
      });

      test('detects Canadian SIN', () {
        final result = PIIDetector().sanitize('SIN: 123-456-789');
        expect(result, contains('[SIN HIDDEN]'));
      });
    });

    group('containsPII and getPIIType', () {
      test('containsPII returns true for email', () {
        expect(PIIDetector().containsPII('john@test.com'), isTrue);
      });

      test('containsPII returns false for plain text', () {
        expect(PIIDetector().containsPII('hello world'), isFalse);
      });

      test('getPIIType returns email type', () {
        expect(PIIDetector().getPIIType('john@test.com'), PIIType.email);
      });

      test('getPIIType returns null for plain text', () {
        expect(PIIDetector().getPIIType('hello world'), isNull);
      });
    });

    group('empty input', () {
      test('sanitize returns empty string for empty input', () {
        expect(PIIDetector().sanitize(''), '');
      });

      test('detect returns empty list for empty input', () {
        expect(PIIDetector().detect(''), isEmpty);
      });
    });
  });
}
