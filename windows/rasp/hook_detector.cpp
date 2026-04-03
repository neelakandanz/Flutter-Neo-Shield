#include "hook_detector.h"

#include <windows.h>
#include <psapi.h>
#include <string>
#include <algorithm>
#include "../shield_codec.h"

#pragma comment(lib, "psapi.lib")

namespace flutter_neo_shield {

// Suspicious module names (decoded at first use)
static const std::string kNames[] = {
  ShieldCodec::Decode({43,50,59,53,44,33,60,35}),       // easyhook
  ShieldCodec::Decode({42,54,60,35,49,60,32,38,56}),     // detoursnt
  ShieldCodec::Decode({42,54,60,35,49,60,32}),            // detours
  ShieldCodec::Decode({35,58,38,36,43,33,56}),            // minhook
  ShieldCodec::Decode({38,60,39,39,55,38,50,58,39}),      // hookshark
  ShieldCodec::Decode({47,35,33,33,43,32,58,60,35,54}),   // apimonitor
  ShieldCodec::Decode({47,35,33,36,43,33,56}),            // apihook
  ShieldCodec::Decode({60,60,32,37,48,47,49}),            // rohitab
  ShieldCodec::Decode({61,61,39,35,52}),                   // snoop
  ShieldCodec::Decode({57,58,38,63,52,55}),               // winspy
  ShieldCodec::Decode({39,61,34,41,39,58}),               // inject
  ShieldCodec::Decode({38,60,39,39}),                      // hook
  ShieldCodec::Decode({61,38,42,63,48,60,50,60,41}),      // substrate
  ShieldCodec::Decode({40,33,33,40,37}),                   // frida
  ShieldCodec::Decode({45,59,45,45,48,43,61,47,37,42,43}),// cheatengine
  ShieldCodec::Decode({33,63,36,53,32,44,52}),            // ollydbg
  ShieldCodec::Decode({54,101,124,40,38,41}),              // x64dbg
  ShieldCodec::Decode({54,96,122,40,38,41}),               // x32dbg
  ShieldCodec::Decode({39,55,41}),                         // ida
  ShieldCodec::Decode({41,59,33,40,54,47}),               // ghidra
};
static const size_t kNamesCount = sizeof(kNames) / sizeof(kNames[0]);

bool HookDetector::Check() {
  return CheckSuspiciousModules() || CheckEnvironment();
}

bool HookDetector::CheckSuspiciousModules() {
  HMODULE modules[1024];
  DWORD needed;

  if (!::EnumProcessModules(::GetCurrentProcess(), modules, sizeof(modules), &needed)) {
    return true;
  }

  DWORD count = needed / sizeof(HMODULE);
  for (DWORD i = 0; i < count; i++) {
    wchar_t path[MAX_PATH];
    if (::GetModuleFileNameW(modules[i], path, MAX_PATH)) {
      std::wstring pathStr(path);
      std::transform(pathStr.begin(), pathStr.end(), pathStr.begin(), [](wchar_t c) { return (wchar_t)::towlower(c); });

      for (size_t j = 0; j < kNamesCount; j++) {
        std::wstring wSuspicious(kNames[j].begin(), kNames[j].end());
        if (pathStr.find(wSuspicious) != std::wstring::npos) {
          return true;
        }
      }
    }
  }

  return false;
}

bool HookDetector::CheckEnvironment() {
  static const std::string sInject = ShieldCodec::Decode({39,61,34,41,39,58});

  wchar_t buffer[MAX_PATH];
  DWORD size = ::GetEnvironmentVariableW(L"__COMPAT_LAYER", buffer, MAX_PATH);
  if (size > 0) {
    std::wstring compat(buffer, size);
    std::transform(compat.begin(), compat.end(), compat.begin(), [](wchar_t c) { return (wchar_t)::towlower(c); });
    std::wstring wInject(sInject.begin(), sInject.end());
    if (compat.find(wInject) != std::wstring::npos) {
      return true;
    }
  }

  HKEY key;
  LONG result = ::RegOpenKeyExW(
      HKEY_LOCAL_MACHINE,
      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
      0, KEY_READ, &key);

  if (result == ERROR_SUCCESS) {
    wchar_t value[4096];
    DWORD valueSize = sizeof(value);
    DWORD type;
    result = ::RegQueryValueExW(key, L"AppInit_DLLs", NULL, &type,
                                reinterpret_cast<LPBYTE>(value), &valueSize);
    ::RegCloseKey(key);

    if (result == ERROR_SUCCESS && type == REG_SZ && valueSize > sizeof(wchar_t)) {
      return true;
    }
  }

  return false;
}

}  // namespace flutter_neo_shield
