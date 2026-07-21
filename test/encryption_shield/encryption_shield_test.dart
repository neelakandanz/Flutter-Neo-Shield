import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_neo_shield/src/encryption_shield/encryption_shield.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  final shield = EncryptionShield.instance;

  group('EncryptionShield (AES-256-GCM)', () {
    test('generateKey returns 32 bytes, generateNonce returns 12', () {
      expect(shield.generateKey().length, 32);
      expect(shield.generateNonce().length, 12);
    });

    test('round-trips a string', () {
      final key = shield.generateKey();
      const plain = 'The quick brown fox — sensitive payload 🦊';
      final ct = shield.encryptString(plain, key);
      expect(shield.decryptString(ct, key), plain);
    });

    test('round-trips a long string (>32 bytes, no keystream repetition)', () {
      final key = shield.generateKey();
      final plain = 'A' * 500;
      final ct = shield.encryptString(plain, key);
      expect(shield.decryptString(ct, key), plain);
    });

    test('same plaintext encrypts to different ciphertext (random nonce)', () {
      final key = shield.generateKey();
      final a = shield.encryptString('repeat', key);
      final b = shield.encryptString('repeat', key);
      expect(a, isNot(equals(b)));
    });

    test('round-trips JSON', () {
      final key = shield.generateKey();
      final json = {
        'user': 'jane',
        'roles': [1, 2, 3],
        'active': true
      };
      final ct = shield.encryptJson(json, key);
      expect(shield.decryptJson(ct, key), json);
    });

    test('wrong key fails authentication (StateError)', () {
      final ct = shield.encryptString('secret', shield.generateKey());
      expect(() => shield.decryptString(ct, shield.generateKey()),
          throwsA(isA<StateError>()));
    });

    test('tampered ciphertext fails authentication (StateError)', () {
      final key = shield.generateKey();
      final ct = shield.encryptString('secret', key);
      final bytes = base64Decode(ct);
      bytes[bytes.length - 1] ^= 0xFF; // flip a tag byte
      final tampered = base64Encode(bytes);
      expect(() => shield.decryptString(tampered, key),
          throwsA(isA<StateError>()));
    });

    test('rejects a non-32-byte key', () {
      expect(() => shield.encryptString('x', Uint8List(16)),
          throwsA(isA<ArgumentError>()));
    });

    test('rejects a too-short ciphertext', () {
      expect(
          () => shield.decryptString(
              base64Encode([1, 2, 3]), shield.generateKey()),
          throwsA(isA<ArgumentError>()));
    });
  });
}
