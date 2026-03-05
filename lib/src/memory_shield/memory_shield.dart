/// Main MemoryShield manager class.
library;

import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

import 'memory_shield_config.dart';

/// Interface for objects that can be securely disposed by [MemoryShield].
abstract class SecureDisposable {
  /// Wipes sensitive data and marks this container as disposed.
  void dispose();
}

/// Singleton manager that tracks all active secure containers and can mass-wipe.
///
/// Tracks [SecureString], [SecureBytes], and [SecureValue] instances and
/// provides lifecycle-aware auto-dispose when the app backgrounds.
///
/// ```dart
/// MemoryShield().init(MemoryShieldConfig(
///   autoDisposeOnBackground: true,
/// ));
/// MemoryShield().bindToLifecycle();
///
/// // On logout:
/// MemoryShield().disposeAll();
/// ```
class MemoryShield with WidgetsBindingObserver {
  /// Returns the singleton [MemoryShield] instance.
  factory MemoryShield() => _instance;

  MemoryShield._internal();

  static final MemoryShield _instance = MemoryShield._internal();

  MemoryShieldConfig _config = const MemoryShieldConfig();
  final Set<SecureDisposable> _activeContainers = {};
  bool _isBound = false;

  /// The method channel for native memory operations.
  static const MethodChannel channel =
      MethodChannel('com.neelakandan.flutter_neo_shield/memory');

  /// The current configuration.
  MemoryShieldConfig get config => _config;

  /// Initializes the MemoryShield with the given [config].
  ///
  /// ```dart
  /// MemoryShield().init(MemoryShieldConfig(
  ///   autoDisposeOnBackground: true,
  ///   defaultMaxAge: Duration(minutes: 5),
  /// ));
  /// ```
  void init(MemoryShieldConfig config) {
    _config = config;
  }

  /// Registers a secure container for tracking.
  ///
  /// Called internally by [SecureString], [SecureBytes], and [SecureValue]
  /// constructors.
  void register(SecureDisposable secureContainer) {
    _activeContainers.add(secureContainer);
  }

  /// Unregisters a secure container from tracking.
  ///
  /// Called internally on dispose.
  void unregister(SecureDisposable secureContainer) {
    _activeContainers.remove(secureContainer);
  }

  /// The number of currently active (undisposed) secure containers.
  ///
  /// ```dart
  /// print(MemoryShield().activeCount); // 3
  /// ```
  int get activeCount => _activeContainers.length;

  /// Disposes ALL active secure containers.
  ///
  /// Call on logout or app termination to wipe all secrets from memory.
  ///
  /// ```dart
  /// MemoryShield().disposeAll();
  /// ```
  void disposeAll() {
    // Copy the set since dispose() modifies it via unregister().
    final containers = Set<SecureDisposable>.from(_activeContainers);
    for (final container in containers) {
      try {
        container.dispose();
      } catch (_) {
        // Container may already be disposed.
      }
    }
    _activeContainers.clear();

    // Also wipe all native memory.
    _tryPlatformWipeAll();
  }

  /// Registers a [WidgetsBinding] observer for auto-dispose on background.
  ///
  /// Required when [MemoryShieldConfig.autoDisposeOnBackground] is true.
  ///
  /// ```dart
  /// MemoryShield().bindToLifecycle();
  /// ```
  void bindToLifecycle() {
    if (_isBound) return;
    _isBound = true;
    WidgetsBinding.instance.addObserver(this);
  }

  /// Unregisters the [WidgetsBinding] observer.
  ///
  /// ```dart
  /// MemoryShield().unbindFromLifecycle();
  /// ```
  void unbindFromLifecycle() {
    if (!_isBound) return;
    _isBound = false;
    WidgetsBinding.instance.removeObserver(this);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused && _config.autoDisposeOnBackground) {
      disposeAll();
    }
  }

  void _tryPlatformWipeAll() {
    if (!_config.enablePlatformWipe) return;

    channel.invokeMethod<void>('wipeAll').catchError((_) {
      // Platform channel unavailable — ignore.
    });
  }

  /// Resets the MemoryShield to its default state.
  ///
  /// Disposes all containers and unbinds from lifecycle.
  ///
  /// ```dart
  /// MemoryShield().reset();
  /// ```
  void reset() {
    disposeAll();
    unbindFromLifecycle();
    _config = const MemoryShieldConfig();
  }
}
