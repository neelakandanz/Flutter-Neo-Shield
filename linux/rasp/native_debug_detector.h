#ifndef FLUTTER_NEO_SHIELD_NATIVE_DEBUG_DETECTOR_H_
#define FLUTTER_NEO_SHIELD_NATIVE_DEBUG_DETECTOR_H_

namespace flutter_neo_shield {

class NativeDebugDetector {
 public:
  static bool Check();
 private:
  static bool CheckTracerPid();
  static bool CheckPtrace();
  static bool CheckWchan();
  static bool CheckTimingAnomaly();
};

}  // namespace flutter_neo_shield

#endif
