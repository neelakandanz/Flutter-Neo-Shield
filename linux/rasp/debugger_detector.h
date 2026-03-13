#ifndef FLUTTER_NEO_SHIELD_DEBUGGER_DETECTOR_H_
#define FLUTTER_NEO_SHIELD_DEBUGGER_DETECTOR_H_

namespace flutter_neo_shield {

class DebuggerDetector {
 public:
  static bool Check();
 private:
  static bool CheckTracerPid();
  static bool CheckParentProcess();
};

}  // namespace flutter_neo_shield

#endif
