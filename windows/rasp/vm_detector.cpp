#include "vm_detector.h"

#include <windows.h>
#include <intrin.h>
#include <string>
#include <algorithm>

namespace flutter_neo_shield {

bool VMDetector::Check() {
  return CheckCPUID() || CheckRegistry() || CheckSystemFirmware();
}

/// Check CPUID hypervisor present bit (bit 31 of ECX from CPUID leaf 1).
///
/// All major hypervisors set this bit: VMware, VirtualBox, Hyper-V, KVM, Xen.
/// On bare metal, this bit is 0.
bool VMDetector::CheckCPUID() {
  int cpuInfo[4] = {0};
  __cpuid(cpuInfo, 1);

  // Bit 31 of ECX = hypervisor present
  return (cpuInfo[2] & (1 << 31)) != 0;
}

/// Check registry for VM-specific service keys.
///
/// VMware, VirtualBox, Hyper-V, and Parallels install services
/// that leave registry footprints.
bool VMDetector::CheckRegistry() {
  struct RegistryCheck {
    HKEY root;
    const wchar_t *path;
  };

  RegistryCheck checks[] = {
    {HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.\\VMware Tools"},
    {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Oracle\\VirtualBox Guest Additions"},
    {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest"},
    {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse"},
    {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxSF"},
    {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxVideo"},
    {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmci"},
    {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmhgfs"},
    {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmx86"},
    {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters"},
    {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\prl_fs"},
    {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\prl_tg"},
  };

  for (const auto &check : checks) {
    HKEY key;
    LONG result = ::RegOpenKeyExW(check.root, check.path, 0, KEY_READ, &key);
    if (result == ERROR_SUCCESS) {
      ::RegCloseKey(key);
      return true;
    }
  }

  return false;
}

/// Check system firmware table for VM identifiers.
///
/// The SMBIOS firmware table contains manufacturer and product strings
/// that identify VMs: "VMware", "VirtualBox", "QEMU", "Microsoft Corporation" (Hyper-V).
bool VMDetector::CheckSystemFirmware() {
  // Get SMBIOS firmware table size
  DWORD size = ::GetSystemFirmwareTable('RSMB', 0, NULL, 0);
  if (size == 0) return false;

  std::vector<BYTE> buffer(size);
  DWORD written = ::GetSystemFirmwareTable('RSMB', 0, buffer.data(), size);
  if (written == 0) return false;

  // Convert to string and search for VM identifiers
  std::string firmware(reinterpret_cast<char *>(buffer.data()), written);
  std::string lower_firmware = firmware;
  std::transform(lower_firmware.begin(), lower_firmware.end(),
                 lower_firmware.begin(), ::tolower);

  const char *vm_strings[] = {
    "vmware", "virtualbox", "vbox", "qemu", "parallels",
    "hyper-v", "xen", "bhyve", "kvm",
  };

  for (const auto &vm_str : vm_strings) {
    if (lower_firmware.find(vm_str) != std::string::npos) {
      return true;
    }
  }

  return false;
}

}  // namespace flutter_neo_shield
