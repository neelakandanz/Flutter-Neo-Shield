#ifndef FLUTTER_NEO_SHIELD_VM_DETECTOR_H_
#define FLUTTER_NEO_SHIELD_VM_DETECTOR_H_

namespace flutter_neo_shield {

class VMDetector {
 public:
  static bool Check();
 private:
  static bool CheckDMI();
  static bool CheckCPUID();
  static bool CheckSystemdDetectVirt();
};

}  // namespace flutter_neo_shield

#endif
