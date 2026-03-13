#ifndef FLUTTER_NEO_SHIELD_INTEGRITY_DETECTOR_H_
#define FLUTTER_NEO_SHIELD_INTEGRITY_DETECTOR_H_

namespace flutter_neo_shield {

class IntegrityDetector {
 public:
  static bool Check();
 private:
  static bool CheckExecutableModified();
  static bool CheckProcExe();
};

}  // namespace flutter_neo_shield

#endif
