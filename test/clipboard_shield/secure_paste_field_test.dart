import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_neo_shield/src/clipboard_shield/clipboard_shield.dart';
import 'package:flutter_neo_shield/src/clipboard_shield/secure_paste_field.dart';
import 'package:flutter_neo_shield/src/core/pii_detector.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    ClipboardShield().reset();
    PIIDetector().reset();

    // Mock clipboard platform channel.
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform,
            (MethodCall methodCall) async {
      if (methodCall.method == 'Clipboard.setData') return null;
      if (methodCall.method == 'Clipboard.getData') {
        return <String, dynamic>{'text': ''};
      }
      return null;
    });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, null);
  });

  Widget buildTestWidget({
    TextEditingController? controller,
    bool clearAfterPaste = true,
    void Function(String)? onPasted,
    void Function(String)? onChanged,
    String? Function(String?)? validator,
  }) {
    return MaterialApp(
      home: Scaffold(
        body: SecurePasteField(
          controller: controller,
          clearAfterPaste: clearAfterPaste,
          onPasted: onPasted,
          onChanged: onChanged,
          validator: validator,
          decoration: const InputDecoration(labelText: 'Test'),
        ),
      ),
    );
  }

  group('SecurePasteField', () {
    testWidgets('renders a TextField', (tester) async {
      await tester.pumpWidget(buildTestWidget());
      expect(find.byType(TextField), findsOneWidget);
    });

    testWidgets('renders TextFormField when validator provided',
        (tester) async {
      await tester.pumpWidget(buildTestWidget(
        validator: (v) => null,
      ));
      expect(find.byType(TextFormField), findsOneWidget);
    });

    testWidgets('onChanged fires on text input', (tester) async {
      String? changedText;
      await tester.pumpWidget(buildTestWidget(
        onChanged: (text) => changedText = text,
      ));

      await tester.enterText(find.byType(TextField), 'hello');
      expect(changedText, 'hello');
    });

    testWidgets('detects paste when 5+ chars inserted', (tester) async {
      String? pastedText;
      final controller = TextEditingController();

      await tester.pumpWidget(buildTestWidget(
        controller: controller,
        onPasted: (text) => pastedText = text,
      ));

      // Simulate typing a short text first.
      await tester.enterText(find.byType(TextField), 'ab');
      await tester.pump();

      // Simulate paste: enter text that adds 5+ chars at once.
      await tester.enterText(find.byType(TextField), 'ab1234567');
      await tester.pump();

      expect(pastedText, isNotNull);
      expect(pastedText, '1234567');
    });

    testWidgets('does not detect paste for short inserts', (tester) async {
      String? pastedText;
      final controller = TextEditingController();

      await tester.pumpWidget(buildTestWidget(
        controller: controller,
        onPasted: (text) => pastedText = text,
      ));

      await tester.enterText(find.byType(TextField), 'ab');
      await tester.pump();

      // Insert only 4 more chars — below threshold.
      await tester.enterText(find.byType(TextField), 'ab1234');
      await tester.pump();

      expect(pastedText, isNull);
    });

    testWidgets('uses external controller when provided', (tester) async {
      final controller = TextEditingController(text: 'initial');
      await tester.pumpWidget(buildTestWidget(controller: controller));

      expect(find.text('initial'), findsOneWidget);
    });

    testWidgets('disposes internal controller when no external',
        (tester) async {
      // Just ensure no error when widget is disposed.
      await tester.pumpWidget(buildTestWidget());
      await tester.pumpWidget(const SizedBox());
      // No errors means success.
    });
  });
}
