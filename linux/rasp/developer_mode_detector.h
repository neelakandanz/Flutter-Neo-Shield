#ifndef FLUTTER_NEO_SHIELD_DEVELOPER_MODE_DETECTOR_H_
#define FLUTTER_NEO_SHIELD_DEVELOPER_MODE_DETECTOR_H_

namespace flutter_neo_shield {

class DeveloperModeDetector {
 public:
  static bool Check();
 private:
  static bool CheckDevToolsInstalled();
  static bool CheckPtraceScope();
};

}  // namespace flutter_neo_shield

#endif
