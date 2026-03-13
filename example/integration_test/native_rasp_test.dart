import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:flutter_neo_shield/flutter_neo_shield.dart';

/// Integration test for native RASP detection on desktop platforms.
///
/// This test runs on the actual platform (macOS/Windows/Linux) and
/// verifies that native method channels respond correctly — i.e.,
/// no MissingPluginException, no crashes, correct return types.
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('Native RASP Detection', () {
    testWidgets('checkDebugger returns bool', (tester) async {
      final result = await RaspShield.checkDebugger();
      expect(result.isDetected, isA<bool>());
    });

    testWidgets('checkRoot returns bool', (tester) async {
      final result = await RaspShield.checkRoot();
      expect(result.isDetected, isA<bool>());
    });

    testWidgets('checkEmulator returns bool (VM detection)', (tester) async {
      final result = await RaspShield.checkEmulator();
      expect(result.isDetected, isA<bool>());
    });

    testWidgets('checkFrida returns bool', (tester) async {
      final result = await RaspShield.checkFrida();
      expect(result.isDetected, isA<bool>());
    });

    testWidgets('checkHooks returns bool', (tester) async {
      final result = await RaspShield.checkHooks();
      expect(result.isDetected, isA<bool>());
    });

    testWidgets('checkIntegrity returns bool', (tester) async {
      final result = await RaspShield.checkIntegrity();
      expect(result.isDetected, isA<bool>());
    });

    testWidgets('checkDeveloperMode returns bool', (tester) async {
      final result = await RaspShield.checkDeveloperMode();
      expect(result.isDetected, isA<bool>());
    });

    testWidgets('checkSignature returns bool', (tester) async {
      final result = await RaspShield.checkSignature();
      expect(result.isDetected, isA<bool>());
    });

    testWidgets('checkNativeDebug returns bool', (tester) async {
      final result = await RaspShield.checkNativeDebug();
      expect(result.isDetected, isA<bool>());
    });

    testWidgets('checkNetworkThreats returns bool', (tester) async {
      final result = await RaspShield.checkNetworkThreats();
      expect(result.isDetected, isA<bool>());
    });

    testWidgets('fullSecurityScan completes with all 10 fields', (tester) async {
      final report = await RaspShield.fullSecurityScan();
      expect(report.isSafe, isA<bool>());
      expect(report.debuggerDetected, isA<bool>());
      expect(report.rootDetected, isA<bool>());
      expect(report.emulatorDetected, isA<bool>());
      expect(report.fridaDetected, isA<bool>());
      expect(report.hookDetected, isA<bool>());
      expect(report.integrityTampered, isA<bool>());
      expect(report.developerModeDetected, isA<bool>());
      expect(report.signatureTampered, isA<bool>());
      expect(report.nativeDebugDetected, isA<bool>());
      expect(report.networkThreatDetected, isA<bool>());

      debugPrint('=== Full Security Scan Results ===');
      debugPrint(report.toString());
    });
  });

  group('Native Screen Protection', () {
    testWidgets('enableProtection returns bool', (tester) async {
      final shield = ScreenShield();
      final result = await shield.enableProtection();
      expect(result, isA<bool>());
    });

    testWidgets('isProtectionActive returns bool', (tester) async {
      final shield = ScreenShield();
      expect(shield.isProtectionActive, isA<bool>());
    });

    testWidgets('disableProtection returns bool', (tester) async {
      final shield = ScreenShield();
      final result = await shield.disableProtection();
      expect(result, isA<bool>());
    });

    testWidgets('isScreenBeingRecorded returns bool', (tester) async {
      final shield = ScreenShield();
      final result = await shield.isScreenBeingRecorded;
      expect(result, isA<bool>());
    });
  });

  group('Native Memory Shield', () {
    testWidgets('SecureString lifecycle works', (tester) async {
      final secureStr = SecureString('test-secret-123');
      expect(secureStr.value, equals('test-secret-123'));
      expect(secureStr.isDisposed, isFalse);

      secureStr.dispose();
      expect(secureStr.isDisposed, isTrue);
    });
  });
}
