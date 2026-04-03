#include "privilege_detector.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <shlobj.h>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

namespace flutter_neo_shield {

bool PrivilegeDetector::Check() {
  return CheckAdmin() || CheckElevatedToken();
}

/// Check if the current user is a member of the Administrators group.
bool PrivilegeDetector::CheckAdmin() {
  return ::IsUserAnAdmin() != FALSE;
}

/// Check the process token integrity level.
/// High or System integrity indicates elevated privileges.
bool PrivilegeDetector::CheckElevatedToken() {
  HANDLE token = NULL;
  if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
    return false;
  }

  TOKEN_ELEVATION elevation;
  DWORD size = sizeof(TOKEN_ELEVATION);
  bool elevated = false;

  if (::GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
    elevated = elevation.TokenIsElevated != 0;
  }

  ::CloseHandle(token);
  return elevated;
}

}  // namespace flutter_neo_shield
