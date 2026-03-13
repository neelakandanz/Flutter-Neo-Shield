#ifndef FLUTTER_NEO_SHIELD_FRIDA_DETECTOR_H_
#define FLUTTER_NEO_SHIELD_FRIDA_DETECTOR_H_

namespace flutter_neo_shield {

/// Detects Frida instrumentation toolkit on Windows.
///
/// Checks:
/// 1. Named pipes (Frida uses \\.\pipe\frida-*)
/// 2. Port scanning (27042, 27043, 4444)
/// 3. Process enumeration for frida-server.exe
/// 4. Loaded DLL scan for frida-agent
class FridaDetector {
 public:
  static bool Check();

 private:
  static bool CheckNamedPipes();
  static bool CheckPorts();
  static bool CheckProcesses();
  static bool CheckLoadedModules();
};

}  // namespace flutter_neo_shield

#endif  // FLUTTER_NEO_SHIELD_FRIDA_DETECTOR_H_
