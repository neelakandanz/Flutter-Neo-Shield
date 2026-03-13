#include "developer_mode_detector.h"

#include <windows.h>
#include <string>

namespace flutter_neo_shield {

bool DeveloperModeDetector::Check() {
  return CheckDeveloperModeRegistry() || CheckSideloadingEnabled();
}

/// Check if Windows Developer Mode is enabled via registry.
///
/// Settings > Update & Security > For Developers > Developer Mode
/// sets AllowDevelopmentWithoutDevLicense = 1
bool DeveloperModeDetector::CheckDeveloperModeRegistry() {
  HKEY key;
  LONG result = ::RegOpenKeyExW(
      HKEY_LOCAL_MACHINE,
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock",
      0, KEY_READ, &key);

  if (result != ERROR_SUCCESS) return false;

  DWORD value = 0;
  DWORD size = sizeof(DWORD);
  DWORD type;

  result = ::RegQueryValueExW(key, L"AllowDevelopmentWithoutDevLicense",
                               NULL, &type, reinterpret_cast<LPBYTE>(&value), &size);
  ::RegCloseKey(key);

  return (result == ERROR_SUCCESS && type == REG_DWORD && value != 0);
}

/// Check if sideloading is enabled (weaker than full Developer Mode).
///
/// AllowAllTrustedApps = 1 allows sideloading of trusted apps.
bool DeveloperModeDetector::CheckSideloadingEnabled() {
  HKEY key;
  LONG result = ::RegOpenKeyExW(
      HKEY_LOCAL_MACHINE,
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock",
      0, KEY_READ, &key);

  if (result != ERROR_SUCCESS) return false;

  DWORD value = 0;
  DWORD size = sizeof(DWORD);
  DWORD type;

  result = ::RegQueryValueExW(key, L"AllowAllTrustedApps",
                               NULL, &type, reinterpret_cast<LPBYTE>(&value), &size);
  ::RegCloseKey(key);

  return (result == ERROR_SUCCESS && type == REG_DWORD && value != 0);
}

/// Check for common debugging and reverse engineering tools.
bool DeveloperModeDetector::CheckDebugToolsPresence() {
  const wchar_t *tool_paths[] = {
    L"C:\\Program Files\\IDA Pro",
    L"C:\\Program Files (x86)\\IDA Pro",
    L"C:\\Program Files\\Ghidra",
    L"C:\\Program Files\\x64dbg",
    L"C:\\Program Files (x86)\\OllyDbg",
  };

  for (const auto &path : tool_paths) {
    DWORD attrs = ::GetFileAttributesW(path);
    if (attrs != INVALID_FILE_ATTRIBUTES &&
        (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
      return true;
    }
  }

  return false;
}

}  // namespace flutter_neo_shield
