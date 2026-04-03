#include "screen_recording_detector.h"

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <algorithm>

namespace flutter_neo_shield {

bool ScreenRecordingDetector::IsRecording() const {
  return CheckRemoteSession() || CheckRecordingProcesses();
}

/// Check for known screen recording processes.
bool ScreenRecordingDetector::CheckRecordingProcesses() const {
  HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) return false;

  const wchar_t *recording_processes[] = {
    L"obs64.exe",
    L"obs32.exe",
    L"obs.exe",
    L"camtasia.exe",
    L"screenflow.exe",
    L"bandicam.exe",
    L"xsplit.exe",
    L"streamlabs obs.exe",
    L"action.exe",           // Mirillis Action
    L"sharex.exe",
    L"loom.exe",
    L"screenrec.exe",
    L"flashbackexpress.exe",
  };

  PROCESSENTRY32W pe = {};
  pe.dwSize = sizeof(PROCESSENTRY32W);
  bool found = false;

  if (::Process32FirstW(snapshot, &pe)) {
    do {
      std::wstring name(pe.szExeFile);
      std::transform(name.begin(), name.end(), name.begin(), [](wchar_t c) { return (wchar_t)::towlower(c); });

      for (const auto &recorder : recording_processes) {
        if (name == recorder) {
          found = true;
          break;
        }
      }
      if (found) break;
    } while (::Process32NextW(snapshot, &pe));
  }

  ::CloseHandle(snapshot);
  return found;
}

/// Check if running in a remote desktop session.
///
/// GetSystemMetrics(SM_REMOTESESSION) returns non-zero when the
/// current session is a Remote Desktop (RDP), Citrix, or similar.
bool ScreenRecordingDetector::CheckRemoteSession() const {
  return ::GetSystemMetrics(SM_REMOTESESSION) != 0;
}

}  // namespace flutter_neo_shield
