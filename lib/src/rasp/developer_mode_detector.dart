import '../platform/rasp_channel.dart';
import 'security_result.dart';

/// Detects if the device has Developer Options / Developer Mode enabled.
///
/// **Android:** Checks `Settings.Global.DEVELOPMENT_SETTINGS_ENABLED`.
/// When Developer Options is enabled the OS exposes USB debugging,
/// mock locations, OEM unlocking and other capabilities that increase
/// the attack surface for financial and sensitive applications.
///
/// **iOS 16+:** Checks whether the Developer Mode toggle
/// (Settings → Privacy & Security → Developer Mode) is enabled.
/// On iOS versions prior to 16, Developer Mode did not exist as a
/// user-facing setting, so the check returns `false`.
class DeveloperModeDetector {
  /// Executes the detection check on the native platform.
  static Future<SecurityResult> check() async {
    final isDetected = await RaspChannel.invokeDetection('checkDeveloperMode');
    return SecurityResult(
      isDetected: isDetected,
      message: isDetected
          ? 'Developer Options / Developer Mode is enabled on this device'
          : null,
    );
  }
}
