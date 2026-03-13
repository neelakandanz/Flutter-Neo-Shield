#ifndef FLUTTER_NEO_SHIELD_DEVELOPER_MODE_DETECTOR_H_
#define FLUTTER_NEO_SHIELD_DEVELOPER_MODE_DETECTOR_H_

namespace flutter_neo_shield {

/// Detects Windows Developer Mode and developer tool presence.
///
/// Checks:
/// 1. Developer Mode registry key (AppModelUnlock)
/// 2. Sideloading enabled registry key
/// 3. Presence of common debugging/RE tools
class DeveloperModeDetector {
 public:
  static bool Check();

 private:
  static bool CheckDeveloperModeRegistry();
  static bool CheckSideloadingEnabled();
  static bool CheckDebugToolsPresence();
};

}  // namespace flutter_neo_shield

#endif  // FLUTTER_NEO_SHIELD_DEVELOPER_MODE_DETECTOR_H_
