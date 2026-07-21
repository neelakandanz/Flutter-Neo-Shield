import '../platform/shield_codec.dart';
import 'package:flutter/services.dart';

/// Biometric Auth Shield — device biometric authentication.
///
/// Wraps the platform biometric prompt: Android `BiometricPrompt`
/// (BIOMETRIC_STRONG / Class 3) and iOS `LAContext` (Face ID / Touch ID),
/// with an optional device-credential (PIN/pattern/password) fallback.
/// Returns a success/failure result; it does not itself sign a challenge.
class BiometricShield {
  BiometricShield._();

  /// Singleton instance of [BiometricShield].
  static final BiometricShield instance = BiometricShield._();

  static final MethodChannel _channel = MethodChannel(
    ShieldCodec.d(ShieldCodec.chBiometric),
  );

  /// Queries the platform for biometric hardware availability.
  ///
  /// Returns a [BiometricAvailability] describing which biometric types
  /// are enrolled and whether the device can authenticate.
  Future<BiometricAvailability> checkAvailability() async {
    try {
      final result = await _channel.invokeMethod<Map>('checkBiometric');
      if (result == null) return BiometricAvailability.unavailable;
      return BiometricAvailability(
        isAvailable: result['available'] as bool? ?? false,
        biometricTypes: (result['types'] as List<dynamic>?)
                ?.map((e) => e.toString())
                .toList() ??
            [],
        canAuthenticate: result['canAuth'] as bool? ?? false,
      );
    } on MissingPluginException {
      return BiometricAvailability.unavailable;
    } on PlatformException {
      return BiometricAvailability.unavailable;
    }
  }

  /// Triggers biometric authentication with the given [reason] prompt.
  ///
  /// Set [allowDeviceCredential] to `true` to allow PIN/password fallback.
  /// Returns a [BiometricResult] indicating success or failure.
  Future<BiometricResult> authenticate(
      {required String reason, bool allowDeviceCredential = false}) async {
    try {
      final result = await _channel.invokeMethod<Map>('authenticate', {
        'reason': reason,
        'allowDeviceCredential': allowDeviceCredential,
      });
      if (result == null) {
        return const BiometricResult(success: false, error: 'No response');
      }
      return BiometricResult(
          success: result['success'] as bool? ?? false,
          error: result['error'] as String?);
    } on MissingPluginException {
      return const BiometricResult(
          success: false, error: 'Platform not supported');
    } on PlatformException catch (e) {
      return BiometricResult(success: false, error: e.message);
    }
  }
}

/// Describes the biometric capabilities of the current device.
class BiometricAvailability {
  /// Creates a [BiometricAvailability] with the given fields.
  const BiometricAvailability(
      {this.isAvailable = false,
      this.biometricTypes = const [],
      this.canAuthenticate = false});

  /// Represents an unavailable/unsupported biometric state.
  static const unavailable = BiometricAvailability();

  /// Whether any biometric hardware is present on the device.
  final bool isAvailable;

  /// List of available biometric types (e.g. "fingerprint", "face").
  final List<String> biometricTypes;

  /// Whether the device can currently authenticate (hardware present and enrolled).
  final bool canAuthenticate;

  @override
  String toString() =>
      'BiometricAvailability(available: $isAvailable, types: $biometricTypes, canAuth: $canAuthenticate)';
}

/// The outcome of a biometric authentication attempt.
class BiometricResult {
  /// Creates a [BiometricResult].
  const BiometricResult({required this.success, this.error});

  /// Whether the authentication was successful.
  final bool success;

  /// Error message if authentication failed, `null` on success.
  final String? error;

  @override
  String toString() => 'BiometricResult(success: $success, error: $error)';
}
