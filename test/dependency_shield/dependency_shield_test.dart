import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter_neo_shield/src/dependency_shield/dependency_shield.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  final shield = DependencyShield.instance;

  setUp(shield.reset);
  tearDown(shield.reset);

  group('DependencyShield (SHA-256)', () {
    test('computeFileHash matches crypto sha256', () async {
      final f = File(
          '${Directory.systemTemp.path}/neo_dep_${DateTime.now().microsecondsSinceEpoch}.lock');
      await f.writeAsString('name: demo\n');
      final expected = sha256.convert(await f.readAsBytes()).toString();
      expect(await shield.computeFileHash(f.path), expected);
      await f.delete();
    });

    test('verifyLockfile passes when hash matches', () async {
      final f = File(
          '${Directory.systemTemp.path}/neo_ok_${DateTime.now().microsecondsSinceEpoch}.lock');
      await f.writeAsString('locked: true\n');
      final hash = (await shield.computeFileHash(f.path))!;
      shield.registerHashes({f.path: hash});
      expect(await shield.verifyLockfile(f.path), isEmpty);
      await f.delete();
    });

    test('verifyLockfile reports a mismatch', () async {
      final f = File(
          '${Directory.systemTemp.path}/neo_bad_${DateTime.now().microsecondsSinceEpoch}.lock');
      await f.writeAsString('locked: true\n');
      shield.registerHashes({f.path: 'deadbeef'});
      final failures = await shield.verifyLockfile(f.path);
      expect(failures, isNotEmpty);
      expect(failures.values.first, contains('Hash mismatch'));
      await f.delete();
    });

    test('no registered hash => no failure', () async {
      final f = File(
          '${Directory.systemTemp.path}/neo_none_${DateTime.now().microsecondsSinceEpoch}.lock');
      await f.writeAsString('x\n');
      expect(await shield.verifyLockfile(f.path), isEmpty);
      await f.delete();
    });
  });
}
