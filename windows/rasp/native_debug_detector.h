#ifndef FLUTTER_NEO_SHIELD_NATIVE_DEBUG_DETECTOR_H_
#define FLUTTER_NEO_SHIELD_NATIVE_DEBUG_DETECTOR_H_

namespace flutter_neo_shield {

/// Native-level debugger detection on Windows.
///
/// Goes beyond IsDebuggerPresent with:
/// 1. NtQueryInformationProcess(ProcessDebugPort)
/// 2. NtQueryInformationProcess(ProcessDebugObjectHandle)
/// 3. Hardware breakpoint detection via debug registers
/// 4. Timing anomaly detection
/// 5. NtSetInformationThread(HideFromDebugger)
class NativeDebugDetector {
 public:
  static bool Check();

 private:
  static bool CheckDebugPort();
  static bool CheckDebugObjectHandle();
  static bool CheckHardwareBreakpoints();
  static bool CheckTimingAnomaly();
};

}  // namespace flutter_neo_shield

#endif  // FLUTTER_NEO_SHIELD_NATIVE_DEBUG_DETECTOR_H_
