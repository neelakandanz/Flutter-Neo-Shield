import 'package:flutter_neo_shield/flutter_neo_shield.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  setUp(() {
    StringShield().reset();
  });

  group('StringShield', () {
    test('is a singleton', () {
      final a = StringShield();
      final b = StringShield();
      expect(identical(a, b), isTrue);
    });

    test('has default config', () {
      expect(
        StringShield().config.defaultStrategy,
        equals(ObfuscationStrategy.xor),
      );
      expect(StringShield().config.enableCache, isFalse);
      expect(StringShield().config.enableStats, isFalse);
    });

    test('init sets config', () {
      StringShield().init(const StringShieldConfig(
        enableCache: false,
        enableStats: true,
        defaultStrategy: ObfuscationStrategy.enhancedXor,
      ));

      expect(StringShield().config.enableCache, isFalse);
      expect(StringShield().config.enableStats, isTrue);
      expect(
        StringShield().config.defaultStrategy,
        equals(ObfuscationStrategy.enhancedXor),
      );
    });

    group('cache', () {
      test('stores and retrieves values when enabled', () {
        StringShield().init(const StringShieldConfig(enableCache: true));

        expect(StringShield().getCached('key1'), isNull);

        StringShield().setCached('key1', 'value1');
        expect(StringShield().getCached('key1'), equals('value1'));
        expect(StringShield().cacheSize, equals(1));
      });

      test('does not store values when disabled', () {
        StringShield().init(const StringShieldConfig(enableCache: false));

        StringShield().setCached('key1', 'value1');
        expect(StringShield().getCached('key1'), isNull);
        expect(StringShield().cacheSize, equals(0));
      });

      test('clearCache removes all entries', () {
        StringShield().init(const StringShieldConfig(enableCache: true));

        StringShield().setCached('key1', 'value1');
        StringShield().setCached('key2', 'value2');
        expect(StringShield().cacheSize, equals(2));

        StringShield().clearCache();
        expect(StringShield().cacheSize, equals(0));
        expect(StringShield().getCached('key1'), isNull);
      });

      test('overwrites existing cache entry', () {
        StringShield().init(const StringShieldConfig(enableCache: true));

        StringShield().setCached('key1', 'value1');
        StringShield().setCached('key1', 'value2');
        expect(StringShield().getCached('key1'), equals('value2'));
        expect(StringShield().cacheSize, equals(1));
      });
    });

    group('stats', () {
      test('tracks counts when stats enabled', () {
        StringShield().init(const StringShieldConfig(enableStats: true));

        StringShield().recordAccess('App.field1');
        StringShield().recordAccess('App.field1');
        StringShield().recordAccess('App.field2');

        expect(StringShield().deobfuscationCount, equals(3));
        expect(
          StringShield().fieldAccessCounts['App.field1'],
          equals(2),
        );
        expect(
          StringShield().fieldAccessCounts['App.field2'],
          equals(1),
        );
      });

      test('does not track when stats disabled', () {
        StringShield().init(const StringShieldConfig(enableStats: false));

        StringShield().recordAccess('App.field1');

        expect(StringShield().deobfuscationCount, equals(0));
        expect(StringShield().fieldAccessCounts, isEmpty);
      });

      test('fieldAccessCounts is unmodifiable', () {
        StringShield().init(const StringShieldConfig(enableStats: true));
        StringShield().recordAccess('App.field1');

        expect(
          () => StringShield().fieldAccessCounts['new'] = 1,
          throwsUnsupportedError,
        );
      });
    });

    test('isCacheEnabled reflects config', () {
      StringShield().init(const StringShieldConfig(enableCache: true));
      expect(StringShield().isCacheEnabled, isTrue);

      StringShield().init(const StringShieldConfig(enableCache: false));
      expect(StringShield().isCacheEnabled, isFalse);
    });

    test('reset clears everything', () {
      StringShield().init(const StringShieldConfig(
        enableCache: true,
        enableStats: true,
        defaultStrategy: ObfuscationStrategy.split,
      ));

      StringShield().setCached('key1', 'value1');
      StringShield().recordAccess('key1');

      StringShield().reset();

      expect(StringShield().cacheSize, equals(0));
      expect(StringShield().deobfuscationCount, equals(0));
      expect(StringShield().fieldAccessCounts, isEmpty);
      expect(
        StringShield().config.defaultStrategy,
        equals(ObfuscationStrategy.xor),
      );
      expect(StringShield().config.enableCache, isFalse);
      expect(StringShield().config.enableStats, isFalse);
    });
  });

  group('StringShieldConfig', () {
    test('has sensible defaults', () {
      const config = StringShieldConfig();
      expect(config.defaultStrategy, equals(ObfuscationStrategy.xor));
      expect(config.enableCache, isFalse);
      expect(config.enableStats, isFalse);
    });

    test('copyWith creates modified copy', () {
      const original = StringShieldConfig();
      final updated = original.copyWith(
        enableStats: true,
        defaultStrategy: ObfuscationStrategy.split,
      );

      expect(updated.enableStats, isTrue);
      expect(updated.defaultStrategy, equals(ObfuscationStrategy.split));
      expect(updated.enableCache, isFalse); // unchanged
    });

    test('copyWith with no args returns equivalent config', () {
      const original = StringShieldConfig(
        enableCache: false,
        enableStats: true,
      );
      final copy = original.copyWith();

      expect(copy.enableCache, equals(original.enableCache));
      expect(copy.enableStats, equals(original.enableStats));
      expect(copy.defaultStrategy, equals(original.defaultStrategy));
    });
  });
}
