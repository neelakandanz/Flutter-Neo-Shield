#ifndef FLUTTER_NEO_SHIELD_SIGNATURE_DETECTOR_H_
#define FLUTTER_NEO_SHIELD_SIGNATURE_DETECTOR_H_

namespace flutter_neo_shield {

class SignatureDetector {
 public:
  static bool Check();
 private:
  static bool CheckElfIntegrity();
  static bool CheckEnvironment();
};

}  // namespace flutter_neo_shield

#endif
