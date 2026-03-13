#ifndef FLUTTER_NEO_SHIELD_INTEGRITY_DETECTOR_H_
#define FLUTTER_NEO_SHIELD_INTEGRITY_DETECTOR_H_

namespace flutter_neo_shield {

/// Detects executable integrity violations on Windows.
///
/// Checks:
/// 1. Authenticode signature verification via WinVerifyTrust
/// 2. Executable image checksum validation
/// 3. Section header integrity
class IntegrityDetector {
 public:
  static bool Check();

 private:
  static bool CheckAuthenticode();
  static bool CheckImageChecksum();
};

}  // namespace flutter_neo_shield

#endif  // FLUTTER_NEO_SHIELD_INTEGRITY_DETECTOR_H_
