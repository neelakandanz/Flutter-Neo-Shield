#ifndef FLUTTER_NEO_SHIELD_HOOK_DETECTOR_H_
#define FLUTTER_NEO_SHIELD_HOOK_DETECTOR_H_

namespace flutter_neo_shield {

/// Detects code injection and hooking on Windows.
///
/// Checks:
/// 1. Loaded DLL scan for suspicious modules
/// 2. Import Address Table (IAT) hook detection
/// 3. Suspicious environment variables
class HookDetector {
 public:
  static bool Check();

 private:
  static bool CheckSuspiciousModules();
  static bool CheckEnvironment();
};

}  // namespace flutter_neo_shield

#endif  // FLUTTER_NEO_SHIELD_HOOK_DETECTOR_H_
