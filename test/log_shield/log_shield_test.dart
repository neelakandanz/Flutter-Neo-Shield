import 'package:flutter_neo_shield/flutter_neo_shield.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  setUp(() {
    LogShield().reset();
    PIIDetector().reset();
  });

  group('LogShield', () {
    group('shieldLog sanitizes PII', () {
      test('email is redacted in log output', () {
        String? capturedMessage;
        String? capturedLevel;

        LogShield().init(LogShieldConfig(
          silentInRelease: false,
          sanitizeInDebug: true,
          outputHandler: (message, level) {
            capturedMessage = message;
            capturedLevel = level;
          },
        ));

        shieldLog('email: john@test.com');

        expect(capturedMessage, isNotNull);
        expect(capturedMessage!, contains('[EMAIL HIDDEN]'));
        expect(capturedMessage!, isNot(contains('john@test.com')));
        expect(capturedLevel, 'INFO');
      });
    });

    group('shieldLog adds level prefix', () {
      test('output contains [INFO] prefix by default', () {
        String? capturedMessage;

        LogShield().init(LogShieldConfig(
          silentInRelease: false,
          outputHandler: (message, level) {
            capturedMessage = message;
          },
        ));

        shieldLog('Hello world');

        expect(capturedMessage, isNotNull);
        expect(capturedMessage!, contains('[INFO]'));
      });

      test('output contains custom level prefix', () {
        String? capturedMessage;

        LogShield().init(LogShieldConfig(
          silentInRelease: false,
          outputHandler: (message, level) {
            capturedMessage = message;
          },
        ));

        shieldLog('Something happened', level: 'WARNING');

        expect(capturedMessage, isNotNull);
        expect(capturedMessage!, contains('[WARNING]'));
      });
    });

    group('shieldLogJson strips sensitive keys', () {
      test('name is redacted and id passes through', () {
        String? capturedMessage;

        LogShield().init(LogShieldConfig(
          silentInRelease: false,
          sanitizeInDebug: true,
          outputHandler: (message, level) {
            capturedMessage = message;
          },
        ));

        shieldLogJson('Data', {'name': 'John', 'id': 123});

        expect(capturedMessage, isNotNull);
        expect(capturedMessage!, contains('[REDACTED]'));
        expect(capturedMessage!, contains('123'));
        expect(capturedMessage!, isNot(contains('"John"')));
      });
    });

    group('shieldLogError sanitizes error messages', () {
      test('PII in error message is redacted', () {
        String? capturedMessage;

        LogShield().init(LogShieldConfig(
          silentInRelease: false,
          sanitizeInDebug: true,
          outputHandler: (message, level) {
            capturedMessage = message;
          },
        ));

        shieldLogError('Failed for john@test.com');

        expect(capturedMessage, isNotNull);
        expect(capturedMessage!, contains('[ERROR]'));
        expect(capturedMessage!, contains('[EMAIL HIDDEN]'));
        expect(capturedMessage!, isNot(contains('john@test.com')));
      });

      test('PII in error object is also sanitized', () {
        String? capturedMessage;

        LogShield().init(LogShieldConfig(
          silentInRelease: false,
          sanitizeInDebug: true,
          outputHandler: (message, level) {
            capturedMessage = message;
          },
        ));

        shieldLogError(
          'Login failed',
          error: Exception('User john@test.com not found'),
        );

        expect(capturedMessage, isNotNull);
        expect(capturedMessage!, contains('[EMAIL HIDDEN]'));
        expect(capturedMessage!, isNot(contains('john@test.com')));
      });
    });

    group('enable() / disable() toggle', () {
      test('disable prevents log output', () {
        String? capturedMessage;

        LogShield().init(LogShieldConfig(
          silentInRelease: false,
          outputHandler: (message, level) {
            capturedMessage = message;
          },
        ));

        LogShield().disable();
        shieldLog('This should not appear');

        expect(capturedMessage, isNull);
      });

      test('enable after disable resumes output', () {
        String? capturedMessage;

        LogShield().init(LogShieldConfig(
          silentInRelease: false,
          outputHandler: (message, level) {
            capturedMessage = message;
          },
        ));

        LogShield().disable();
        shieldLog('Hidden');
        expect(capturedMessage, isNull);

        LogShield().enable();
        shieldLog('Visible');
        expect(capturedMessage, isNotNull);
        expect(capturedMessage!, contains('Visible'));
      });

      test('isEnabled reflects current state', () {
        expect(LogShield().isEnabled, isTrue);
        LogShield().disable();
        expect(LogShield().isEnabled, isFalse);
        LogShield().enable();
        expect(LogShield().isEnabled, isTrue);
      });
    });

    group('showRedactionNotice', () {
      test('appends redaction notice when PII is found and option enabled', () {
        String? capturedMessage;

        LogShield().init(LogShieldConfig(
          silentInRelease: false,
          sanitizeInDebug: true,
          showRedactionNotice: true,
          outputHandler: (message, level) {
            capturedMessage = message;
          },
        ));

        shieldLog('Contact john@test.com');

        expect(capturedMessage, isNotNull);
        expect(capturedMessage!, contains('[LogShield:'));
        expect(capturedMessage!, contains('redacted'));
      });

      test('no redaction notice when no PII is present', () {
        String? capturedMessage;

        LogShield().init(LogShieldConfig(
          silentInRelease: false,
          sanitizeInDebug: true,
          showRedactionNotice: true,
          outputHandler: (message, level) {
            capturedMessage = message;
          },
        ));

        shieldLog('Hello world');

        expect(capturedMessage, isNotNull);
        expect(capturedMessage!, isNot(contains('[LogShield:')));
      });

      test('no redaction notice when option is disabled', () {
        String? capturedMessage;

        LogShield().init(LogShieldConfig(
          silentInRelease: false,
          sanitizeInDebug: true,
          showRedactionNotice: false,
          outputHandler: (message, level) {
            capturedMessage = message;
          },
        ));

        shieldLog('Contact john@test.com');

        expect(capturedMessage, isNotNull);
        expect(capturedMessage!, isNot(contains('[LogShield:')));
      });
    });

    group('outputHandler receives sanitized message', () {
      test('output handler callback receives sanitized text', () {
        final messages = <String>[];

        LogShield().init(LogShieldConfig(
          silentInRelease: false,
          sanitizeInDebug: true,
          outputHandler: (message, level) {
            messages.add(message);
          },
        ));

        shieldLog('SSN: 123-45-6789');

        expect(messages, hasLength(1));
        expect(messages.first, contains('[SSN HIDDEN]'));
        expect(messages.first, isNot(contains('123-45-6789')));
      });

      test('output handler receives correct level', () {
        String? receivedLevel;

        LogShield().init(LogShieldConfig(
          silentInRelease: false,
          outputHandler: (message, level) {
            receivedLevel = level;
          },
        ));

        shieldLog('Test', level: 'ERROR');

        expect(receivedLevel, 'ERROR');
      });
    });

    group('sanitizeInDebug flag', () {
      test('when false, PII is NOT hidden in debug mode', () {
        String? capturedMessage;

        LogShield().init(LogShieldConfig(
          silentInRelease: false,
          sanitizeInDebug: false,
          outputHandler: (message, level) {
            capturedMessage = message;
          },
        ));

        shieldLog('email: john@test.com');

        expect(capturedMessage, isNotNull);
        expect(capturedMessage!, contains('john@test.com'));
        expect(capturedMessage!, isNot(contains('[EMAIL HIDDEN]')));
      });

      test('when true, PII IS hidden in debug mode', () {
        String? capturedMessage;

        LogShield().init(LogShieldConfig(
          silentInRelease: false,
          sanitizeInDebug: true,
          outputHandler: (message, level) {
            capturedMessage = message;
          },
        ));

        shieldLog('email: john@test.com');

        expect(capturedMessage, isNotNull);
        expect(capturedMessage!, contains('[EMAIL HIDDEN]'));
        expect(capturedMessage!, isNot(contains('john@test.com')));
      });
    });
  });
}
