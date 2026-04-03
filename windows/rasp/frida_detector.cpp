#include "frida_detector.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <string>
#include <algorithm>
#include "../shield_codec.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")

namespace flutter_neo_shield {

// "frida" encoded
static const std::string kFrida = ShieldCodec::Decode({40, 33, 33, 40, 37});

bool FridaDetector::Check() {
  return CheckNamedPipes() || CheckPorts() || CheckProcesses() || CheckLoadedModules();
}

bool FridaDetector::CheckNamedPipes() {
  WIN32_FIND_DATAW findData;
  HANDLE hFind = ::FindFirstFileW(L"\\\\.\\pipe\\*", &findData);
  if (hFind == INVALID_HANDLE_VALUE) return false;

  // Convert search string to wide
  std::wstring wFrida(kFrida.begin(), kFrida.end());

  bool found = false;
  do {
    std::wstring pipeName(findData.cFileName);
    std::transform(pipeName.begin(), pipeName.end(), pipeName.begin(), [](wchar_t c) { return (wchar_t)::towlower(c); });
    if (pipeName.find(wFrida) != std::wstring::npos) {
      found = true;
      break;
    }
  } while (::FindNextFileW(hFind, &findData));

  ::FindClose(hFind);
  return found;
}

bool FridaDetector::CheckPorts() {
  WSADATA wsaData;
  if (::WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return false;

  int frida_ports[] = {27042, 27043, 4444};
  bool found = false;

  for (int port : frida_ports) {
    SOCKET sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) continue;

    DWORD timeout = 1000;
    ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u_short>(port));
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

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

bool FridaDetector::CheckProcesses() {
  HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) return false;

  std::wstring wFrida(kFrida.begin(), kFrida.end());

  PROCESSENTRY32W pe = {};
  pe.dwSize = sizeof(PROCESSENTRY32W);

  bool found = false;
  if (::Process32FirstW(snapshot, &pe)) {
    do {
      std::wstring name(pe.szExeFile);
      std::transform(name.begin(), name.end(), name.begin(), [](wchar_t c) { return (wchar_t)::towlower(c); });
      if (name.find(wFrida) != std::wstring::npos) {
        found = true;
        break;
      }
    } while (::Process32NextW(snapshot, &pe));
  }

  ::CloseHandle(snapshot);
  return found;
}

bool FridaDetector::CheckLoadedModules() {
  HMODULE modules[1024];
  DWORD needed;

  if (!::EnumProcessModules(::GetCurrentProcess(), modules, sizeof(modules), &needed)) {
    return true;
  }

  std::wstring wFrida(kFrida.begin(), kFrida.end());

  DWORD count = needed / sizeof(HMODULE);
  for (DWORD i = 0; i < count; i++) {
    wchar_t name[MAX_PATH];
    if (::GetModuleFileNameW(modules[i], name, MAX_PATH)) {
      std::wstring nameStr(name);
      std::transform(nameStr.begin(), nameStr.end(), nameStr.begin(), [](wchar_t c) { return (wchar_t)::towlower(c); });
      if (nameStr.find(wFrida) != std::wstring::npos) {
        return true;
      }
    }
  }

  return false;
}

}  // namespace flutter_neo_shield
