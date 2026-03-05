/// Detection statistics tracker for flutter_neo_shield.
library;

import 'dart:collection';

import 'pii_type.dart';

/// A detection event record containing the type and timestamp.
///
/// Does NOT store the actual matched text for privacy.
class DetectionEvent {
  /// Creates a [DetectionEvent] with the given type and timestamp.
  const DetectionEvent({
    required this.type,
    required this.timestamp,
  });

  /// The type of PII that was detected.
  final PIIType type;

  /// When the detection occurred.
  final DateTime timestamp;

  /// Converts this event to a JSON-compatible map.
  ///
  /// ```dart
  /// final json = event.toJson();
  /// // {'type': 'email', 'timestamp': '2024-01-01T00:00:00.000'}
  /// ```
  Map<String, dynamic> toJson() => {
        'type': type.name,
        'timestamp': timestamp.toIso8601String(),
      };
}

/// Tracks PII detection statistics across the application.
///
/// Only active when [ShieldConfig.enableReporting] is true.
/// Never stores actual matched PII text — only type and timestamp.
///
/// ```dart
/// final report = ShieldReport();
/// report.recordDetection(PIIType.email);
/// print(report.totalDetections); // 1
/// ```
class ShieldReport {
  /// Creates a new [ShieldReport] instance.
  ShieldReport();

  int _totalDetections = 0;
  final Map<PIIType, int> _countsByType = {};
  DateTime? _lastDetectionTimestamp;
  final Queue<DetectionEvent> _recentEvents = Queue<DetectionEvent>();

  /// Maximum number of recent events to keep.
  static const int maxRecentEvents = 100;

  /// Total number of PII detections recorded.
  int get totalDetections => _totalDetections;

  /// Detection counts broken down by PII type.
  Map<PIIType, int> get countsByType => Map.unmodifiable(_countsByType);

  /// Timestamp of the most recent detection, or null if none recorded.
  DateTime? get lastDetectionTimestamp => _lastDetectionTimestamp;

  /// The most recent detection events (up to [maxRecentEvents]).
  List<DetectionEvent> get recentEvents =>
      List.unmodifiable(_recentEvents.toList());

  /// Records a detection event for the given [type].
  ///
  /// Increments counters and adds to the recent events list.
  ///
  /// ```dart
  /// report.recordDetection(PIIType.email);
  /// report.recordDetection(PIIType.phone);
  /// print(report.totalDetections); // 2
  /// ```
  void recordDetection(PIIType type) {
    _totalDetections++;
    _countsByType[type] = (_countsByType[type] ?? 0) + 1;
    _lastDetectionTimestamp = DateTime.now();

    final event = DetectionEvent(
      type: type,
      timestamp: _lastDetectionTimestamp!,
    );
    _recentEvents.add(event);
    if (_recentEvents.length > maxRecentEvents) {
      _recentEvents.removeFirst();
    }
  }

  /// Returns statistics as a map.
  ///
  /// ```dart
  /// final stats = report.getStats();
  /// print(stats['totalDetections']);
  /// ```
  Map<String, dynamic> getStats() {
    return {
      'totalDetections': _totalDetections,
      'countsByType': {
        for (final entry in _countsByType.entries) entry.key.name: entry.value,
      },
      'lastDetectionTimestamp': _lastDetectionTimestamp?.toIso8601String(),
      'recentEventsCount': _recentEvents.length,
    };
  }

  /// Resets all statistics to zero.
  ///
  /// ```dart
  /// report.reset();
  /// print(report.totalDetections); // 0
  /// ```
  void reset() {
    _totalDetections = 0;
    _countsByType.clear();
    _lastDetectionTimestamp = null;
    _recentEvents.clear();
  }

  /// Converts all statistics to a JSON-compatible map.
  ///
  /// ```dart
  /// final json = report.toJson();
  /// ```
  Map<String, dynamic> toJson() {
    return {
      'totalDetections': _totalDetections,
      'countsByType': {
        for (final entry in _countsByType.entries) entry.key.name: entry.value,
      },
      'lastDetectionTimestamp': _lastDetectionTimestamp?.toIso8601String(),
      'recentEvents': _recentEvents.map((e) => e.toJson()).toList(),
    };
  }
}
