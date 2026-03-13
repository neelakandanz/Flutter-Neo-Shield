#ifndef FLUTTER_NEO_SHIELD_SCREEN_RECORDING_DETECTOR_H_
#define FLUTTER_NEO_SHIELD_SCREEN_RECORDING_DETECTOR_H_

namespace flutter_neo_shield {

/// Detects screen recording and remote desktop on Windows.
///
/// Checks:
/// 1. Known screen recording processes
/// 2. Remote desktop session detection
/// 3. Virtual display adapters
class ScreenRecordingDetector {
 public:
  bool IsRecording() const;

 private:
  bool CheckRecordingProcesses() const;
  bool CheckRemoteSession() const;
};

}  // namespace flutter_neo_shield

#endif  // FLUTTER_NEO_SHIELD_SCREEN_RECORDING_DETECTOR_H_
