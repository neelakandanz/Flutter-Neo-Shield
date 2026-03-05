/// Configuration for the Memory Shield module.
library;

/// Configuration for the [MemoryShield] module.
///
/// Controls auto-dispose behavior, platform channel usage, and
/// default max age for secure containers.
///
/// ```dart
/// final config = MemoryShieldConfig(
///   autoDisposeOnBackground: true,
///   defaultMaxAge: Duration(minutes: 5),
/// );
/// ```
class MemoryShieldConfig {
  /// Creates a [MemoryShieldConfig] with the specified options.
  const MemoryShieldConfig({
    this.autoDisposeOnBackground = false,
    this.autoDisposeOnLogout = true,
    this.defaultMaxAge,
    this.enablePlatformWipe = true,
  });

  /// If true, all secure containers are disposed when the app backgrounds.
  ///
  /// **Warning:** This is aggressive — even a brief app switch (e.g., to
  /// check a 2FA code) will wipe all secrets. The app will need to
  /// re-authenticate or re-fetch secrets when the user returns.
  ///
  /// Requires calling [MemoryShield.bindToLifecycle] to register the
  /// lifecycle observer.
  final bool autoDisposeOnBackground;

  /// Convenience flag indicating intent to dispose on logout.
  ///
  /// The developer should call [MemoryShield.disposeAll] manually on logout.
  final bool autoDisposeOnLogout;

  /// Default max age for secure containers.
  ///
  /// If set, all [SecureString], [SecureBytes], and [SecureValue] instances
  /// will auto-dispose after this duration unless overridden individually.
  /// Set to null to disable auto-expiry.
  final Duration? defaultMaxAge;

  /// Whether to use native platform channels for memory wipe.
  ///
  /// When true and platform channels are available (Android/iOS),
  /// sensitive data is stored and wiped natively. Falls back to
  /// pure Dart approach when unavailable.
  final bool enablePlatformWipe;
}
