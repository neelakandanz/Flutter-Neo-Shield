#include "hook_detector.h"

#include <windows.h>
#include <psapi.h>
#include <string>
#include <algorithm>

#pragma comment(lib, "psapi.lib")

namespace flutter_neo_shield {

bool HookDetector::Check() {
  return CheckSuspiciousModules() || CheckEnvironment();
}

/// Scan loaded DLLs for known hooking/injection frameworks.
bool HookDetector::CheckSuspiciousModules() {
  HMODULE modules[1024];
  DWORD needed;

  if (!::EnumProcessModules(::GetCurrentProcess(), modules, sizeof(modules), &needed)) {
    return false;
  }

  const wchar_t *suspicious_names[] = {
    L"easyhook",
    L"detoursnt",
    L"detours",
    L"minhook",
    L"hookshark",
    L"apimonitor",
    L"apihook",
    L"rohitab",
    L"snoop",
    L"winspy",
    L"inject",
    L"hook",
    L"substrate",
    L"frida",
    L"cheatengine",
    L"ollydbg",
    L"x64dbg",
    L"x32dbg",
    L"ida",
    L"ghidra",
  };

  DWORD count = needed / sizeof(HMODULE);
  for (DWORD i = 0; i < count; i++) {
    wchar_t path[MAX_PATH];
    if (::GetModuleFileNameW(modules[i], path, MAX_PATH)) {
      std::wstring pathStr(path);
      std::transform(pathStr.begin(), pathStr.end(), pathStr.begin(), ::towlower);

      for (const auto &suspicious : suspicious_names) {
        if (pathStr.find(suspicious) != std::wstring::npos) {
          return true;
        }
      }
    }
  }

  return false;
}

/// Check for injection-related environment variables.
bool HookDetector::CheckEnvironment() {
  // AppInit_DLLs mechanism — Windows loads DLLs listed here into every process
  wchar_t buffer[MAX_PATH];
  DWORD size = ::GetEnvironmentVariableW(L"__COMPAT_LAYER", buffer, MAX_PATH);
  if (size > 0) {
    std::wstring compat(buffer, size);
    std::transform(compat.begin(), compat.end(), compat.begin(), ::towlower);
    if (compat.find(L"inject") != std::wstring::npos) {
      return true;
    }
  }

  // Check registry for AppInit_DLLs
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
      // Non-empty AppInit_DLLs means DLLs are being injected
      return true;
    }
  }

  return false;
}

}  // namespace flutter_neo_shield
