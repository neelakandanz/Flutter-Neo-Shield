import 'package:flutter_neo_shield/src/cert_pin_shield/cert_pin_shield.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  final shield = CertPinShield.instance;

  setUp(shield.unpinAll);
  tearDown(shield.unpinAll);

  group('CertPinShield', () {
    test('unpinned host is not enforced (validateCertificate => true)', () {
      expect(shield.isPinned('example.com'), isFalse);
      expect(shield.validateCertificate('example.com', 'anything'), isTrue);
    });

    test('pinned host: matching hash passes, others fail (fail-closed)', () {
      shield.pin('example.com', ['AAAABBBBCCCC']);
      expect(shield.isPinned('example.com'), isTrue);
      expect(shield.validateCertificate('example.com', 'AAAABBBBCCCC'), isTrue);
      expect(shield.validateCertificate('example.com', 'WRONGHASH'), isFalse);
    });

    test('normalizes sha256/ prefix and surrounding whitespace', () {
      shield.pin('api.example.com', [' sha256/AAAABBBBCCCC ']);
      expect(shield.validateCertificate('api.example.com', 'AAAABBBBCCCC'),
          isTrue);
      expect(shield.getPins('api.example.com'), contains('AAAABBBBCCCC'));
    });

    test('validateCertificateChain fail-closed on null cert for pinned host',
        () {
      shield.pin('example.com', ['AAAA']);
      expect(shield.validateCertificateChain('example.com', null), isFalse);
      // unpinned host with null cert is allowed (pinning not requested)
      expect(shield.validateCertificateChain('other.com', null), isTrue);
    });

    test('unpin / unpinAll clear state', () {
      shield.pin('a.com', ['x']);
      shield.pin('b.com', ['y']);
      shield.unpin('a.com');
      expect(shield.isPinned('a.com'), isFalse);
      expect(shield.isPinned('b.com'), isTrue);
      shield.unpinAll();
      expect(shield.hasPins, isFalse);
    });
  });
}
