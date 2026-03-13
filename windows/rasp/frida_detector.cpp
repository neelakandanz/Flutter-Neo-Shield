#include "frida_detector.h"

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <string>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")

namespace flutter_neo_shield {

bool FridaDetector::Check() {
  return CheckNamedPipes() || CheckPorts() || CheckProcesses() || CheckLoadedModules();
}

/// Check for Frida named pipes.
///
/// Frida-server creates named pipes for IPC with frida-agent.
bool FridaDetector::CheckNamedPipes() {
  WIN32_FIND_DATAW findData;
  HANDLE hFind = ::FindFirstFileW(L"\\\\.\\pipe\\*", &findData);
  if (hFind == INVALID_HANDLE_VALUE) return false;

  bool found = false;
  do {
    std::wstring pipeName(findData.cFileName);
    std::transform(pipeName.begin(), pipeName.end(), pipeName.begin(), ::towlower);
    if (pipeName.find(L"frida") != std::wstring::npos) {
      found = true;
      break;
    }
  } while (::FindNextFileW(hFind, &findData));

  ::FindClose(hFind);
  return found;
}

/// Scan Frida default ports on localhost.
bool FridaDetector::CheckPorts() {
  WSADATA wsaData;
  if (::WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return false;

  int frida_ports[] = {27042, 27043, 4444};
  bool found = false;

  for (int port : frida_ports) {
    SOCKET sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) continue;

    // Set connection timeout to 1 second
    DWORD timeout = 1000;
    ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u_short>(port));
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (::connect(sock, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0) {
      found = true;
      ::closesocket(sock);
      break;
    }
    ::closesocket(sock);
  }

  ::WSACleanup();
  return found;
}

/// Check running processes for frida-server.
bool FridaDetector::CheckProcesses() {
  HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) return false;

  PROCESSENTRY32W pe = {};
  pe.dwSize = sizeof(PROCESSENTRY32W);

  bool found = false;
  if (::Process32FirstW(snapshot, &pe)) {
    do {
      std::wstring name(pe.szExeFile);
      std::transform(name.begin(), name.end(), name.begin(), ::towlower);
      if (name.find(L"frida") != std::wstring::npos) {
        found = true;
        break;
      }
    } while (::Process32NextW(snapshot, &pe));
  }

  ::CloseHandle(snapshot);
  return found;
}

/// Scan loaded DLLs in current process for frida-agent.
bool FridaDetector::CheckLoadedModules() {
  HMODULE modules[1024];
  DWORD needed;

  if (!::EnumProcessModules(::GetCurrentProcess(), modules, sizeof(modules), &needed)) {
    return false;
  }

  DWORD count = needed / sizeof(HMODULE);
  for (DWORD i = 0; i < count; i++) {
    wchar_t name[MAX_PATH];
    if (::GetModuleFileNameW(modules[i], name, MAX_PATH)) {
      std::wstring nameStr(name);
      std::transform(nameStr.begin(), nameStr.end(), nameStr.begin(), ::towlower);
      if (nameStr.find(L"frida") != std::wstring::npos) {
        return true;
      }
    }
  }

  return false;
}

}  // namespace flutter_neo_shield
