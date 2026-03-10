import 'package:flutter/services.dart';
import 'package:flutter_neo_shield/src/platform/rasp_channel.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    RaspChannel.resetForTesting();
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
      const MethodChannel('com.neelakandan.flutter_neo_shield/rasp'),
      null,
    );
  });

  group('RaspChannel', () {
    test('failClosed defaults to true', () {
      expect(RaspChannel.failClosed, isTrue);
    });

    test('configure sets failClosed', () {
      RaspChannel.configure(failClosed: false);
      expect(RaspChannel.failClosed, isFalse);
    });

    test('configure can only be called once', () {
      RaspChannel.configure(failClosed: false);
      RaspChannel.configure(failClosed: true); // ignored
      expect(RaspChannel.failClosed, isFalse);
    });

    test('resetForTesting restores defaults', () {
      RaspChannel.configure(failClosed: false);
      RaspChannel.resetForTesting();
      expect(RaspChannel.failClosed, isTrue);
    });

    test('resetForTesting allows reconfiguration', () {
      RaspChannel.configure(failClosed: false);
      RaspChannel.resetForTesting();
      RaspChannel.configure(failClosed: false);
      expect(RaspChannel.failClosed, isFalse);
    });

    test('invokeDetection returns native result when true', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
        const MethodChannel('com.neelakandan.flutter_neo_shield/rasp'),
        (MethodCall methodCall) async => true,
      );

      final result = await RaspChannel.invokeDetection('checkDebugger');
      expect(result, isTrue);
    });

    test('invokeDetection returns native result when false', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
        const MethodChannel('com.neelakandan.flutter_neo_shield/rasp'),
        (MethodCall methodCall) async => false,
      );

      final result = await RaspChannel.invokeDetection('checkDebugger');
      expect(result, isFalse);
    });

    test('invokeDetection returns failClosed on MissingPluginException',
        () async {
      // No mock handler set — will throw MissingPluginException.
      final result = await RaspChannel.invokeDetection('checkDebugger');
      expect(result, isTrue); // fail-closed default
    });

    test(
        'invokeDetection returns false when fail-open on MissingPluginException',
        () async {
      RaspChannel.configure(failClosed: false);
      final result = await RaspChannel.invokeDetection('checkDebugger');
      expect(result, isFalse); // fail-open
    });

    test('invokeDetection returns failClosed on PlatformException', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
        const MethodChannel('com.neelakandan.flutter_neo_shield/rasp'),
        (MethodCall methodCall) async {
          throw PlatformException(code: 'ERROR', message: 'test');
        },
      );

      final result = await RaspChannel.invokeDetection('checkDebugger');
      expect(result, isTrue); // fail-closed
    });

    test('invokeDetection passes arguments to native', () async {
      Map<String, dynamic>? receivedArgs;

      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
        const MethodChannel('com.neelakandan.flutter_neo_shield/rasp'),
        (MethodCall methodCall) async {
          receivedArgs = Map<String, dynamic>.from(
            methodCall.arguments as Map,
          );
          return false;
        },
      );

      await RaspChannel.invokeDetection(
        'checkIntegrity',
        {'key': 'value'},
      );

      expect(receivedArgs, {'key': 'value'});
    });
  });
}
