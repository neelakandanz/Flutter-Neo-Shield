/// Main entry point for flutter_neo_shield.
library;

import 'clipboard_shield/clipboard_shield.dart';
import 'clipboard_shield/clipboard_shield_config.dart';
import 'core/pii_detector.dart';
import 'core/shield_config.dart';
import 'core/shield_report.dart';
import 'log_shield/log_shield.dart';
import 'log_shield/log_shield_config.dart';
import 'memory_shield/memory_shield.dart';
import 'memory_shield/memory_shield_config.dart';
import 'string_shield/string_shield.dart';
import 'string_shield/string_shield_config.dart';

/// Main entry point and convenience class for flutter_neo_shield.
///
/// Initializes all modules at once. Call [init] in your `main()` function
/// before `runApp()`.
///
/// ```dart
/// void main() {
///   WidgetsFlutterBinding.ensureInitialized();
///   FlutterNeoShield.init(
///     config: ShieldConfig(enableReporting: true),
///     logConfig: LogShieldConfig(silentInRelease: true),
///   );
///   runApp(MyApp());
/// }
/// ```
class FlutterNeoShield {
  FlutterNeoShield._();

  static bool _initialized = false;
  static bool _warnedAboutInit = false;

  /// Whether [init] has been called.
  ///
  /// ```dart
  /// if (FlutterNeoShield.isInitialized) { ... }
  /// ```
  static bool get isInitialized => _initialized;

  /// Logs a one-time warning if modules are used before [init].
  static void _warnIfNotInitialized() {
    if (!_initialized && !_warnedAboutInit) {
      _warnedAboutInit = true;
      assert(() {
        // ignore: avoid_print
        print(
          '[flutter_neo_shield] WARNING: FlutterNeoShield.init() has not '
          'been called. Modules are running with default configuration. '
          'Call FlutterNeoShield.init() in main() before runApp().',
        );
        return true;
      }());
    }
  }

  /// Initializes all flutter_neo_shield modules with optional configuration.
  ///
  /// Can be called with no arguments for sensible defaults.
  ///
  /// ```dart
  /// FlutterNeoShield.init(
  ///   config: ShieldConfig(enableReporting: true),
  ///   logConfig: LogShieldConfig(silentInRelease: true),
  ///   clipboardConfig: ClipboardShieldConfig(defaultExpiry: Duration(seconds: 15)),
  ///   memoryConfig: MemoryShieldConfig(autoDisposeOnBackground: true),
  ///   stringShieldConfig: StringShieldConfig(enableCache: true),
  /// );
  /// ```
  static void init({
    ShieldConfig? config,
    LogShieldConfig? logConfig,
    ClipboardShieldConfig? clipboardConfig,
    MemoryShieldConfig? memoryConfig,
    StringShieldConfig? stringShieldConfig,
  }) {
    final shieldConfig = config ?? const ShieldConfig();

    PIIDetector().configure(shieldConfig);

    if (logConfig != null) {
      LogShield().init(logConfig);
    }

    if (clipboardConfig != null) {
      ClipboardShield().init(clipboardConfig);
    }

    if (memoryConfig != null) {
      MemoryShield().init(memoryConfig);
    }

    if (stringShieldConfig != null) {
      StringShield().init(stringShieldConfig);
    }

    _initialized = true;
  }

  /// Access the shared PII detection engine.
  ///
  /// ```dart
  /// FlutterNeoShield.detector.registerName('John');
  /// FlutterNeoShield.detector.sanitize('Hello John');
  /// ```
  static PIIDetector get detector {
    _warnIfNotInitialized();
    return PIIDetector();
  }

  /// Access the LogShield module.
  ///
  /// ```dart
  /// FlutterNeoShield.log.log('message');
  /// ```
  static LogShield get log {
    _warnIfNotInitialized();
    return LogShield();
  }

  /// Access the ClipboardShield module.
  ///
  /// ```dart
  /// await FlutterNeoShield.clipboard.copy('text');
  /// ```
  static ClipboardShield get clipboard {
    _warnIfNotInitialized();
    return ClipboardShield();
  }

  /// Access the MemoryShield module.
  ///
  /// ```dart
  /// FlutterNeoShield.memory.disposeAll();
  /// ```
  static MemoryShield get memory {
    _warnIfNotInitialized();
    return MemoryShield();
  }

  /// Access the StringShield module.
  ///
  /// ```dart
  /// FlutterNeoShield.stringShield.clearCache();
  /// ```
  static StringShield get stringShield {
    _warnIfNotInitialized();
    return StringShield();
  }

  /// Access the detection report, or null if reporting is disabled.
  ///
  /// ```dart
  /// final stats = FlutterNeoShield.report?.getStats();
  /// ```
  static ShieldReport? get report => PIIDetector().report;

  /// Resets all modules to default state.
  ///
  /// Useful in tests.
  ///
  /// ```dart
  /// FlutterNeoShield.reset();
  /// ```
  static void reset() {
    PIIDetector().reset();
    LogShield().reset();
    ClipboardShield().reset();
    MemoryShield().reset();
    StringShield().reset();
    _initialized = false;
    _warnedAboutInit = false;
  }
}
