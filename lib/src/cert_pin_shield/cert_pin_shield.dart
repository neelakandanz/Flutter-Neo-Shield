import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';

/// Certificate Pinning Shield — prevents MITM attacks by pinning TLS
/// certificates to known-good SHA-256 hashes.
///
/// A "pin" is the **Base64-encoded SHA-256 digest of the certificate's DER
/// encoding**. Compute the pin for a live certificate with
/// [certificateSha256], or from the CLI:
///
/// ```sh
/// openssl s_client -connect example.com:443 </dev/null 2>/dev/null \
///   | openssl x509 -outform der | openssl dgst -sha256 -binary | base64
/// ```
///
/// Enforcement model:
/// * [createPinnedClient] rejects any connection whose certificate chain is
///   untrusted **unless** the presented leaf certificate matches a pin for that
///   host — this covers private-CA / self-signed pinning and blocks MITM certs.
/// * Because Dart's [HttpClient.badCertificateCallback] only fires for
///   certificates that already fail the system trust chain, a MITM using a
///   *validly-signed* certificate that is not your pin will still pass the
///   callback. To fully enforce pinning against valid-CA certificates, verify
///   the response certificate yourself with [validateCertificateChain]:
///
///   ```dart
///   final res = await request.close();
///   if (!CertPinShield.instance.validateCertificateChain(host, res.certificate)) {
///     res.detachSocket().then((s) => s.destroy());
///     throw const TlsException('Certificate pin mismatch');
///   }
///   ```
class CertPinShield {
  CertPinShield._();

  /// Singleton instance of [CertPinShield].
  static final CertPinShield instance = CertPinShield._();

  final Map<String, Set<String>> _pins = {};

  /// Pin a [host] to one or more Base64 SHA-256 certificate hashes.
  void pin(String host, List<String> sha256Hashes) {
    _pins[host] = sha256Hashes.map(_normalize).toSet();
  }

  /// Remove pins for a [host].
  void unpin(String host) => _pins.remove(host);

  /// Remove all pins.
  void unpinAll() => _pins.clear();

  /// Get pinned hashes for a [host].
  Set<String>? getPins(String host) => _pins[host];

  /// Whether any pins are configured.
  bool get hasPins => _pins.isNotEmpty;

  /// Whether a [host] has at least one configured pin.
  bool isPinned(String host) => (_pins[host]?.isNotEmpty) ?? false;

  /// Computes the pin for [cert] — the Base64-encoded SHA-256 digest of its
  /// DER encoding. This is the value stored via [pin] and compared during
  /// validation.
  String certificateSha256(X509Certificate cert) =>
      base64.encode(sha256.convert(cert.der).bytes);

  /// Validates a live [cert] against the pins configured for [host].
  ///
  /// Fail-closed: returns `false` when [host] is pinned but [cert] is `null`
  /// or its hash is not among the pins. Returns `true` only when the hash
  /// matches, or when [host] has no pins configured (pinning not requested
  /// for that host).
  bool validateCertificateChain(String host, X509Certificate? cert) {
    final pins = _pins[host];
    if (pins == null || pins.isEmpty) return true;
    if (cert == null) return false;
    return pins.contains(certificateSha256(cert));
  }

  /// Validates a pre-computed [certHash] (Base64 SHA-256 of the cert DER)
  /// against the pins for [host].
  ///
  /// Fail-closed: returns `false` when [host] is pinned and [certHash] does not
  /// match. Returns `true` when [host] has no pins configured.
  bool validateCertificate(String host, String certHash) {
    final pins = _pins[host];
    if (pins == null || pins.isEmpty) return true;
    return pins.contains(_normalize(certHash));
  }

  /// Creates an [HttpClient] that enforces certificate pinning.
  ///
  /// The [HttpClient.badCertificateCallback] accepts an otherwise-untrusted
  /// certificate **only** if it matches a configured pin for the host, and
  /// rejects everything else. Returns `null` on web where [HttpClient] is
  /// unavailable. See the class docs for fully enforcing pins against
  /// validly-signed certificates via [validateCertificateChain].
  HttpClient? createPinnedClient() {
    if (kIsWeb) return null;
    final client = HttpClient();
    client.badCertificateCallback =
        (X509Certificate cert, String host, int port) {
      final pins = _pins[host];
      // No pin override for bad chains: reject untrusted certs on unpinned hosts.
      if (pins == null || pins.isEmpty) return false;
      return pins.contains(certificateSha256(cert));
    };
    return client;
  }

  String _normalize(String hash) =>
      hash.trim().replaceFirst(RegExp(r'^sha256/', caseSensitive: false), '');
}
