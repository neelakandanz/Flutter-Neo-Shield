import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_neo_shield/flutter_neo_shield.dart';

/// Demo screen for the Screen Shield module.
///
/// This screen demonstrates three core capabilities:
///
/// 1. **Screen Protection** — Toggle `FLAG_SECURE` (Android) or secure text
///    field layer (iOS) to block screenshots and screen recording. When enabled,
///    any capture attempt shows a black/blank screen instead of app content.
///
/// 2. **App Switcher Guard** — On Android, `FLAG_SECURE` automatically blanks
///    the recent-apps thumbnail. On iOS, a blur overlay is added when the app
///    resigns active state (user presses home or opens app switcher).
///
/// 3. **Detection Streams** — On iOS, the plugin fires events when:
///    - A screenshot is taken (`onScreenshotDetected`)
///    - Screen recording starts or stops (`onRecordingStateChanged`)
///    Android blocks capture silently via `FLAG_SECURE` and does not fire events.
///
/// The "Sensitive Content" card at the bottom simulates a screen with
/// confidential data. Try taking a screenshot with protection enabled
/// to verify that the content appears black/blank in the captured image.
class ScreenShieldDemo extends StatefulWidget {
  /// Creates the Screen Shield demo screen.
  const ScreenShieldDemo({super.key});

  @override
  State<ScreenShieldDemo> createState() => _ScreenShieldDemoState();
}

class _ScreenShieldDemoState extends State<ScreenShieldDemo> {
  // ScreenShield is a singleton — ScreenShield() always returns the same instance.
  final _shield = ScreenShield();

  // Local UI state, kept in sync with native state via callbacks.
  bool _protectionActive = false;
  bool _appSwitcherActive = false;
  bool _isRecording = false;

  // Event log — shows detection events in reverse chronological order.
  final List<String> _events = [];

  // Stream subscriptions — must be cancelled in dispose() to prevent leaks.
  StreamSubscription<ScreenshotEvent>? _screenshotSub;
  StreamSubscription<RecordingStateEvent>? _recordingSub;

  @override
  void initState() {
    super.initState();

    // Query the current native state on load.
    _refreshState();

    // Subscribe to screenshot detection events (iOS only).
    // On Android, screenshots are silently blocked — no event fires.
    _screenshotSub = _shield.onScreenshotDetected.listen((event) {
      setState(() {
        _events.insert(
            0, 'Screenshot detected at ${_formatTime(event.timestamp)}');
      });
    });

    // Subscribe to screen recording state changes (iOS only).
    // Fires when the user starts/stops the built-in screen recorder,
    // AirPlay mirroring, or any other capture session.
    _recordingSub = _shield.onRecordingStateChanged.listen((event) {
      setState(() {
        _isRecording = event.isRecording;
        final action = event.isRecording ? 'started' : 'stopped';
        _events.insert(
            0, 'Recording $action at ${_formatTime(event.timestamp)}');
      });
    });
  }

  /// Query the native platform for the current protection and recording state.
  Future<void> _refreshState() async {
    final protection = await _shield.isProtectionActiveNative;
    final recording = await _shield.isScreenBeingRecorded;
    if (mounted) {
      setState(() {
        _protectionActive = protection;
        _isRecording = recording;
      });
    }
  }

  String _formatTime(DateTime dt) {
    return '${dt.hour.toString().padLeft(2, '0')}:'
        '${dt.minute.toString().padLeft(2, '0')}:'
        '${dt.second.toString().padLeft(2, '0')}';
  }

  @override
  void dispose() {
    // Always cancel stream subscriptions to avoid memory leaks.
    _screenshotSub?.cancel();
    _recordingSub?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // ─── Card 1: Screen Protection Toggle ───
        // Enables/disables FLAG_SECURE (Android) or secure layer (iOS).
        // When ON: screenshots and recordings capture a black/blank screen.
        // When OFF: app content is visible in captures as normal.
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Screen Protection', style: theme.textTheme.titleMedium),
                const SizedBox(height: 4),
                Text(
                  'Blocks screenshots and screen recording. '
                  'On Android, the captured image will be black. '
                  'On iOS, the content area will be blank.',
                  style: theme.textTheme.bodySmall,
                ),
                const SizedBox(height: 12),
                Row(
                  children: [
                    Icon(
                      _protectionActive ? Icons.lock : Icons.lock_open,
                      color: _protectionActive ? Colors.green : Colors.red,
                    ),
                    const SizedBox(width: 8),
                    Text(
                      _protectionActive ? 'Active' : 'Inactive',
                      style: TextStyle(
                        fontWeight: FontWeight.bold,
                        color: _protectionActive ? Colors.green : Colors.red,
                      ),
                    ),
                    const Spacer(),
                    FilledButton(
                      onPressed: () async {
                        if (_protectionActive) {
                          await _shield.disableProtection();
                        } else {
                          await _shield.enableProtection();
                        }
                        setState(() {
                          _protectionActive = _shield.isProtectionActive;
                        });
                      },
                      child: Text(_protectionActive ? 'Disable' : 'Enable'),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),

        const SizedBox(height: 8),

        // ─── Card 2: App Switcher Guard Toggle ───
        // Android: FLAG_SECURE already blanks the recent-apps thumbnail
        //          (so this is effectively the same as screen protection).
        // iOS: Adds a UIVisualEffectView blur overlay when the app resigns
        //       active, hiding content in the app switcher.
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('App Switcher Guard', style: theme.textTheme.titleMedium),
                const SizedBox(height: 4),
                Text(
                  'Hides app content in the recent apps view. '
                  'Try pressing the home button to see the blurred thumbnail.',
                  style: theme.textTheme.bodySmall,
                ),
                const SizedBox(height: 12),
                Row(
                  children: [
                    Icon(
                      _appSwitcherActive
                          ? Icons.visibility_off
                          : Icons.visibility,
                      color: _appSwitcherActive ? Colors.green : Colors.red,
                    ),
                    const SizedBox(width: 8),
                    Text(
                      _appSwitcherActive ? 'Active' : 'Inactive',
                      style: TextStyle(
                        fontWeight: FontWeight.bold,
                        color: _appSwitcherActive ? Colors.green : Colors.red,
                      ),
                    ),
                    const Spacer(),
                    FilledButton(
                      onPressed: () async {
                        if (_appSwitcherActive) {
                          await _shield.disableAppSwitcherGuard();
                        } else {
                          await _shield.enableAppSwitcherGuard();
                        }
                        setState(() {
                          _appSwitcherActive = _shield.isAppSwitcherGuardActive;
                        });
                      },
                      child: Text(_appSwitcherActive ? 'Disable' : 'Enable'),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),

        const SizedBox(height: 8),

        // ─── Card 3: Recording Status ───
        // Shows whether screen recording is currently active.
        // iOS: Uses UIScreen.isCaptured (updated via capturedDidChangeNotification).
        // Android: Heuristic check for virtual/presentation displays.
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Recording Status', style: theme.textTheme.titleMedium),
                const SizedBox(height: 4),
                Text(
                  'Detects if the screen is being recorded or mirrored. '
                  'On iOS, this updates in real-time. On Android, tap refresh.',
                  style: theme.textTheme.bodySmall,
                ),
                const SizedBox(height: 12),
                Row(
                  children: [
                    Icon(
                      _isRecording
                          ? Icons.fiber_manual_record
                          : Icons.stop_circle_outlined,
                      color: _isRecording ? Colors.red : Colors.grey,
                    ),
                    const SizedBox(width: 8),
                    Text(
                      _isRecording ? 'Recording detected!' : 'Not recording',
                      style: TextStyle(
                        color: _isRecording ? Colors.red : null,
                        fontWeight:
                            _isRecording ? FontWeight.bold : FontWeight.normal,
                      ),
                    ),
                    const Spacer(),
                    IconButton(
                      icon: const Icon(Icons.refresh),
                      tooltip: 'Refresh recording state',
                      onPressed: _refreshState,
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),

        const SizedBox(height: 8),

        // ─── Card 4: Sensitive Content (Test Area) ───
        // This card simulates a screen with confidential data.
        // Take a screenshot with protection enabled and check the result:
        //   - Android: the entire screenshot will be black.
        //   - iOS: this content area will be blank/white.
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Sensitive Content (Test Area)',
                    style: theme.textTheme.titleMedium),
                const SizedBox(height: 4),
                Text(
                  'Take a screenshot while protection is enabled. '
                  'This content should appear black (Android) or blank (iOS) '
                  'in the captured image.',
                  style: theme.textTheme.bodySmall,
                ),
                const SizedBox(height: 12),
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: theme.colorScheme.errorContainer,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Column(
                    children: [
                      Text(
                        'Account: **** **** **** 4242',
                        style: theme.textTheme.bodyLarge,
                      ),
                      Text(
                        'Balance: \$12,345.67',
                        style: theme.textTheme.bodyLarge,
                      ),
                      Text(
                        'SSN: 123-45-6789',
                        style: theme.textTheme.bodyLarge,
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),

        // ─── Card 5: Event Log ───
        // Shows screenshot and recording detection events.
        // Only populated on iOS — Android blocks capture silently.
        if (_events.isNotEmpty) ...[
          const SizedBox(height: 8),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Text('Events', style: theme.textTheme.titleMedium),
                      const Spacer(),
                      TextButton(
                        onPressed: () => setState(() => _events.clear()),
                        child: const Text('Clear'),
                      ),
                    ],
                  ),
                  const SizedBox(height: 4),
                  Text(
                    'Screenshot and recording detection events (iOS only).',
                    style: theme.textTheme.bodySmall,
                  ),
                  const SizedBox(height: 8),
                  ...(_events.take(20).map((e) => Padding(
                        padding: const EdgeInsets.only(bottom: 4),
                        child: Text(e, style: theme.textTheme.bodySmall),
                      ))),
                ],
              ),
            ),
          ),
        ],
      ],
    );
  }
}
