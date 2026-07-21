import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// Data-at-Rest Encryption Shield — authenticated **AES-256-GCM** encryption
/// for local data (strings, bytes, JSON).
///
/// AES-256-GCM provides both confidentiality and integrity: every ciphertext
/// carries a 128-bit authentication tag, so tampering (or a wrong key) is
/// detected on decrypt instead of silently returning garbage.
///
/// A fresh random 96-bit nonce is generated for every [encryptString] call and
/// stored alongside the ciphertext, so encrypting the same plaintext twice
/// produces different output. Output layout (before Base64):
/// `nonce (12 bytes) ‖ ciphertext ‖ tag (16 bytes)`.
///
/// ```dart
/// final key = EncryptionShield.instance.generateKey(); // 32 bytes
/// final ct = EncryptionShield.instance.encryptString('secret', key);
/// final pt = EncryptionShield.instance.decryptString(ct, key); // 'secret'
/// ```
class EncryptionShield {
  EncryptionShield._();

  /// Singleton instance of [EncryptionShield].
  static final EncryptionShield instance = EncryptionShield._();

  /// GCM nonce length in bytes (96-bit, the recommended size for AES-GCM).
  static const int _nonceLength = 12;

  /// GCM authentication tag length in bits (128-bit).
  static const int _macBits = 128;

  /// AES-256 key length in bytes.
  static const int _keyLength = 32;

  /// Generates a cryptographically secure 256-bit (32-byte) random key.
  Uint8List generateKey() => _randomBytes(_keyLength);

  /// Generates a cryptographically secure 96-bit (12-byte) GCM nonce.
  ///
  /// A fresh nonce is generated automatically by [encryptString]; you normally
  /// do not need to call this directly.
  Uint8List generateNonce() => _randomBytes(_nonceLength);

  /// Deprecated alias for [generateNonce].
  ///
  /// AES-GCM uses a 96-bit (12-byte) nonce, not a 128-bit IV. Retained for
  /// backwards compatibility.
  @Deprecated('Use generateNonce(); AES-GCM uses a 96-bit (12-byte) nonce.')
  Uint8List generateIV() => generateNonce();

  /// Encrypts a [plaintext] string with a 256-bit [key] using AES-256-GCM.
  ///
  /// Returns Base64(`nonce ‖ ciphertext ‖ tag`). A random nonce is generated
  /// per call. Throws [ArgumentError] if [key] is not exactly 32 bytes.
  String encryptString(String plaintext, Uint8List key) {
    _requireKey(key);
    final nonce = generateNonce();
    final data = Uint8List.fromList(utf8.encode(plaintext));
    final sealed =
        _gcm(forEncryption: true, key: key, nonce: nonce, input: data);
    final combined = Uint8List(nonce.length + sealed.length)
      ..setRange(0, nonce.length, nonce)
      ..setRange(nonce.length, nonce.length + sealed.length, sealed);
    return base64Encode(combined);
  }

  /// Decrypts a Base64 [ciphertext] produced by [encryptString] using [key].
  ///
  /// Throws [ArgumentError] if [key] is not 32 bytes or the payload is too
  /// short, and [StateError] if the authentication tag does not verify
  /// (tampered ciphertext or wrong key).
  String decryptString(String ciphertext, Uint8List key) {
    _requireKey(key);
    final combined = base64Decode(ciphertext);
    if (combined.length < _nonceLength + (_macBits ~/ 8)) {
      throw ArgumentError(
          'Ciphertext is too short to be valid AES-256-GCM output.');
    }
    final nonce = Uint8List.sublistView(combined, 0, _nonceLength);
    final sealed = Uint8List.sublistView(combined, _nonceLength);
    try {
      final plain =
          _gcm(forEncryption: false, key: key, nonce: nonce, input: sealed);
      return utf8.decode(plain);
    } on InvalidCipherTextException {
      throw StateError(
        'Decryption failed: authentication tag mismatch '
        '(tampered ciphertext or wrong key).',
      );
    }
  }

  /// Encrypts a JSON [json] map with AES-256-GCM and returns a Base64 ciphertext.
  String encryptJson(Map<String, dynamic> json, Uint8List key) =>
      encryptString(jsonEncode(json), key);

  /// Decrypts a Base64 [ciphertext] and parses it as a JSON [Map].
  Map<String, dynamic> decryptJson(String ciphertext, Uint8List key) =>
      jsonDecode(decryptString(ciphertext, key)) as Map<String, dynamic>;

  /// Raw XOR of [data] with a repeating [key].
  ///
  /// **Not encryption.** This is a reversible byte transform with no
  /// confidentiality or integrity guarantees. Use [encryptString] /
  /// [decryptString] (AES-256-GCM) for anything sensitive.
  @Deprecated(
      'XOR is not secure. Use encryptString/decryptString (AES-256-GCM).')
  Uint8List xorEncrypt(Uint8List data, Uint8List key) {
    final result = Uint8List(data.length);
    for (var i = 0; i < data.length; i++) {
      result[i] = data[i] ^ key[i % key.length];
    }
    return result;
  }

  /// Symmetric inverse of [xorEncrypt].
  @Deprecated(
      'XOR is not secure. Use encryptString/decryptString (AES-256-GCM).')
  Uint8List xorDecrypt(Uint8List data, Uint8List key) => xorEncrypt(data, key);

  Uint8List _gcm({
    required bool forEncryption,
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List input,
  }) {
    final cipher = GCMBlockCipher(AESEngine())
      ..init(
        forEncryption,
        AEADParameters(KeyParameter(key), _macBits, nonce, Uint8List(0)),
      );
    return cipher.process(input);
  }

  void _requireKey(Uint8List key) {
    if (key.length != _keyLength) {
      throw ArgumentError(
        'AES-256 requires a $_keyLength-byte key, got ${key.length} bytes. '
        'Use EncryptionShield.instance.generateKey().',
      );
    }
  }

  Uint8List _randomBytes(int n) {
    final random = Random.secure();
    return Uint8List.fromList(
        List<int>.generate(n, (_) => random.nextInt(256)));
  }
}
