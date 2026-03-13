#ifndef FLUTTER_NEO_SHIELD_PRIVILEGE_DETECTOR_H_
#define FLUTTER_NEO_SHIELD_PRIVILEGE_DETECTOR_H_

namespace flutter_neo_shield {

/// Detects elevated privilege execution on Windows.
///
/// Checks:
/// 1. IsUserAnAdmin() — running as administrator
/// 2. Token integrity level — SYSTEM or High integrity
class PrivilegeDetector {
 public:
  static bool Check();

 private:
  static bool CheckAdmin();
  static bool CheckElevatedToken();
};

}  // namespace flutter_neo_shield

#endif  // FLUTTER_NEO_SHIELD_PRIVILEGE_DETECTOR_H_
