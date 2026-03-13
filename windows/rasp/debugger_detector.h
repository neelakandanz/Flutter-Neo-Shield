#ifndef FLUTTER_NEO_SHIELD_DEBUGGER_DETECTOR_H_
#define FLUTTER_NEO_SHIELD_DEBUGGER_DETECTOR_H_

namespace flutter_neo_shield {

/// Detects debugger attachment on Windows.
///
/// Uses multiple Win32 APIs:
/// 1. IsDebuggerPresent() — user-mode debugger check
/// 2. CheckRemoteDebuggerPresent() — kernel-mode debugger check
/// 3. NtGlobalFlag in PEB — anti-debug flag
class DebuggerDetector {
 public:
  static bool Check();

 private:
  static bool CheckIsDebuggerPresent();
  static bool CheckRemoteDebugger();
  static bool CheckNtGlobalFlag();
};

}  // namespace flutter_neo_shield

#endif  // FLUTTER_NEO_SHIELD_DEBUGGER_DETECTOR_H_
