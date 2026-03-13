#ifndef FLUTTER_NEO_SHIELD_HOOK_DETECTOR_H_
#define FLUTTER_NEO_SHIELD_HOOK_DETECTOR_H_

namespace flutter_neo_shield {

class HookDetector {
 public:
  static bool Check();
 private:
  static bool CheckLDPreload();
  static bool CheckMaps();
};

}  // namespace flutter_neo_shield

#endif
