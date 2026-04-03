#include "vm_detector.h"

#include <windows.h>
#include <intrin.h>
#include <string>
#include <algorithm>
#include "../shield_codec.h"

namespace flutter_neo_shield {

// VM firmware strings (decoded at first use)
static const std::string kVmStrings[] = {
  ShieldCodec::Decode({56,62,63,45,54,43}),         // vmware
  ShieldCodec::Decode({56,58,58,56,49,47,63,42,35,60}), // virtualbox
  ShieldCodec::Decode({56,49,39,52}),                 // vbox
  ShieldCodec::Decode({63,54,37,57}),                 // qemu
  ShieldCodec::Decode({62,50,58,45,40,34,54,36,63}), // parallels
  ShieldCodec::Decode({38,42,56,41,54,99,37}),       // hyper-v
  ShieldCodec::Decode({54,54,38}),                     // xen
  ShieldCodec::Decode({44,59,49,58,33}),              // bhyve
  ShieldCodec::Decode({37,37,37}),                     // kvm
};
static const size_t kVmStringsCount = sizeof(kVmStrings) / sizeof(kVmStrings[0]);

bool VMDetector::Check() {
  return CheckCPUID() || CheckRegistry() || CheckSystemFirmware();
}

bool VMDetector::CheckCPUID() {
  int cpuInfo[4] = {0};
  __cpuid(cpuInfo, 1);
  return (cpuInfo[2] & (1 << 31)) != 0;
}

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

bool VMDetector::CheckSystemFirmware() {
  DWORD size = ::GetSystemFirmwareTable('RSMB', 0, NULL, 0);
  if (size == 0) return false;

  std::vector<BYTE> buffer(size);
  DWORD written = ::GetSystemFirmwareTable('RSMB', 0, buffer.data(), size);
  if (written == 0) return false;

  std::string firmware(reinterpret_cast<char *>(buffer.data()), written);
  std::string lower_firmware = firmware;
  std::transform(lower_firmware.begin(), lower_firmware.end(),
                 lower_firmware.begin(), [](char c) { return (char)::tolower((unsigned char)c); });

  for (size_t i = 0; i < kVmStringsCount; i++) {
    if (lower_firmware.find(kVmStrings[i]) != std::string::npos) {
      return true;
    }
  }

  return false;
}

}  // namespace flutter_neo_shield
