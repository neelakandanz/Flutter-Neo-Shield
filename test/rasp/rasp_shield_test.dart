import 'package:flutter/services.dart';
import 'package:flutter_neo_shield/src/platform/rasp_channel.dart';
import 'package:flutter_neo_shield/src/rasp/rasp_shield.dart';
import 'package:flutter_neo_shield/src/rasp/security_mode.dart';
import 'package:flutter_neo_shield/src/rasp/security_result.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('com.neelakandan.flutter_neo_shield/rasp');

  /// Maps method names to return values.
  Map<String, bool> nativeResults = {};

  setUp(() {
    RaspChannel.resetForTesting();
    nativeResults = {
      'checkDebugger': false,
      'checkRoot': false,
      'checkEmulator': false,
      'checkFrida': false,
      'checkHooks': false,
      'checkIntegrity': false,
      'checkDeveloperMode': false,
    };

    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (MethodCall methodCall) async {
      return nativeResults[methodCall.method] ?? false;
    });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  group('Individual checks', () {
    test('checkDebugger returns SecurityResult', () async {
      nativeResults['checkDebugger'] = true;
      final result = await RaspShield.checkDebugger();
      expect(result, isA<SecurityResult>());
      expect(result.isDetected, isTrue);
    });

    test('checkRoot returns SecurityResult', () async {
      final result = await RaspShield.checkRoot();
      expect(result.isDetected, isFalse);
    });

    test('checkEmulator returns SecurityResult', () async {
      nativeResults['checkEmulator'] = true;
      final result = await RaspShield.checkEmulator();
      expect(result.isDetected, isTrue);
    });

    test('checkFrida returns SecurityResult', () async {
      final result = await RaspShield.checkFrida();
      expect(result.isDetected, isFalse);
    });

    test('checkHooks returns SecurityResult', () async {
      final result = await RaspShield.checkHooks();
      expect(result.isDetected, isFalse);
    });

    test('checkIntegrity returns SecurityResult', () async {
      final result = await RaspShield.checkIntegrity();
      expect(result.isDetected, isFalse);
    });

    test('checkDeveloperMode returns SecurityResult when not detected',
        () async {
      final result = await RaspShield.checkDeveloperMode();
      expect(result, isA<SecurityResult>());
      expect(result.isDetected, isFalse);
    });

    test('checkDeveloperMode returns detected when enabled', () async {
      nativeResults['checkDeveloperMode'] = true;
      final result = await RaspShield.checkDeveloperMode();
      expect(result.isDetected, isTrue);
      expect(result.message, isNotNull);
    });
  });

  group('fullSecurityScan', () {
    test('returns safe report when all checks pass', () async {
      final report = await RaspShield.fullSecurityScan();
      expect(report.isSafe, isTrue);
      expect(report.debuggerDetected, isFalse);
      expect(report.rootDetected, isFalse);
      expect(report.emulatorDetected, isFalse);
      expect(report.fridaDetected, isFalse);
      expect(report.hookDetected, isFalse);
      expect(report.integrityTampered, isFalse);
      expect(report.developerModeDetected, isFalse);
    });

    test('returns unsafe report when threat detected', () async {
      nativeResults['checkRoot'] = true;
      final report = await RaspShield.fullSecurityScan();
      expect(report.isSafe, isFalse);
      expect(report.rootDetected, isTrue);
    });

    test('silent mode returns report without throwing', () async {
      nativeResults['checkDebugger'] = true;
      final report = await RaspShield.fullSecurityScan(
        mode: SecurityMode.silent,
      );
      expect(report.isSafe, isFalse);
      expect(report.debuggerDetected, isTrue);
    });

    test('strict mode throws SecurityException on threat', () async {
      nativeResults['checkFrida'] = true;
      expect(
        () => RaspShield.fullSecurityScan(mode: SecurityMode.strict),
        throwsA(isA<SecurityException>()),
      );
    });

    test('strict mode does not throw when safe', () async {
      final report = await RaspShield.fullSecurityScan(
        mode: SecurityMode.strict,
      );
      expect(report.isSafe, isTrue);
    });

    test('warn mode logs warning (does not throw)', () async {
      nativeResults['checkEmulator'] = true;
      final report = await RaspShield.fullSecurityScan(
        mode: SecurityMode.warn,
      );
      expect(report.isSafe, isFalse);
      expect(report.emulatorDetected, isTrue);
    });

    test('custom mode invokes onThreat callback', () async {
      nativeResults['checkHooks'] = true;
      SecurityReport? capturedReport;

      final report = await RaspShield.fullSecurityScan(
        mode: SecurityMode.custom,
        onThreat: (r) => capturedReport = r,
      );

      expect(capturedReport, isNotNull);
      expect(capturedReport!.hookDetected, isTrue);
      expect(report.hookDetected, isTrue);
    });

    test('custom mode does not invoke callback when safe', () async {
      bool called = false;
      await RaspShield.fullSecurityScan(
        mode: SecurityMode.custom,
        onThreat: (_) => called = true,
      );
      expect(called, isFalse);
    });

    test('multiple threats reported correctly', () async {
      nativeResults['checkDebugger'] = true;
      nativeResults['checkRoot'] = true;
      nativeResults['checkFrida'] = true;

      final report = await RaspShield.fullSecurityScan();
      expect(report.isSafe, isFalse);
      expect(report.debuggerDetected, isTrue);
      expect(report.rootDetected, isTrue);
      expect(report.fridaDetected, isTrue);
      expect(report.emulatorDetected, isFalse);
      expect(report.hookDetected, isFalse);
      expect(report.integrityTampered, isFalse);
      expect(report.developerModeDetected, isFalse);
    });

    test('developerModeDetected reported correctly in full scan', () async {
      nativeResults['checkDeveloperMode'] = true;
      final report = await RaspShield.fullSecurityScan();
      expect(report.isSafe, isFalse);
      expect(report.developerModeDetected, isTrue);
    });
  });

  group('SecurityResult', () {
    test('toString includes all fields', () {
      const result = SecurityResult(
        isDetected: true,
        message: 'test message',
      );
      expect(result.toString(), contains('isDetected: true'));
      expect(result.toString(), contains('test message'));
    });

    test('additionalData is accessible', () {
      const result = SecurityResult(
        isDetected: true,
        additionalData: {'port': 27042},
      );
      expect(result.additionalData!['port'], 27042);
    });
  });

  group('SecurityReport', () {
    test('toString includes all fields', () {
      const report = SecurityReport(
        debuggerDetected: true,
        rootDetected: false,
        emulatorDetected: false,
        fridaDetected: true,
        hookDetected: false,
        integrityTampered: false,
      );
      final str = report.toString();
      expect(str, contains('safe: false'));
      expect(str, contains('debugger: true'));
      expect(str, contains('frida: true'));
      expect(str, contains('developerMode: false'));
    });

    test('isSafe is true when all false', () {
      const report = SecurityReport(
        debuggerDetected: false,
        rootDetected: false,
        emulatorDetected: false,
        fridaDetected: false,
        hookDetected: false,
        integrityTampered: false,
      );
      expect(report.isSafe, isTrue);
    });

    test('isSafe is false when any true', () {
      const report = SecurityReport(
        debuggerDetected: false,
        rootDetected: false,
        emulatorDetected: false,
        fridaDetected: false,
        hookDetected: false,
        integrityTampered: true,
      );
      expect(report.isSafe, isFalse);
    });

    test('isSafe is false when only developerModeDetected is true', () {
      const report = SecurityReport(
        debuggerDetected: false,
        rootDetected: false,
        emulatorDetected: false,
        fridaDetected: false,
        hookDetected: false,
        integrityTampered: false,
        developerModeDetected: true,
      );
      expect(report.isSafe, isFalse);
      expect(report.developerModeDetected, isTrue);
    });
  });

  group('SecurityMode', () {
    test('enum has all expected values', () {
      expect(SecurityMode.values, hasLength(4));
      expect(SecurityMode.values, contains(SecurityMode.strict));
      expect(SecurityMode.values, contains(SecurityMode.warn));
      expect(SecurityMode.values, contains(SecurityMode.silent));
      expect(SecurityMode.values, contains(SecurityMode.custom));
    });
  });

  group('SecurityException', () {
    test('message is accessible', () {
      const e = SecurityException('test');
      expect(e.message, 'test');
    });

    test('toString includes message', () {
      const e = SecurityException('threat detected');
      expect(e.toString(), 'SecurityException: threat detected');
    });
  });
}
