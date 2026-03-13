#ifndef FLUTTER_NEO_SHIELD_VM_DETECTOR_H_
#define FLUTTER_NEO_SHIELD_VM_DETECTOR_H_

namespace flutter_neo_shield {

/// Detects virtual machine environments on Windows.
///
/// Checks:
/// 1. WMI Win32_ComputerSystem for VM model/manufacturer
/// 2. Registry keys for VM-specific services
/// 3. CPUID hypervisor present bit
/// 4. Known VM MAC address prefixes
class VMDetector {
 public:
  static bool Check();

 private:
  static bool CheckRegistry();
  static bool CheckCPUID();
  static bool CheckSystemFirmware();
};

}  // namespace flutter_neo_shield

#endif  // FLUTTER_NEO_SHIELD_VM_DETECTOR_H_
