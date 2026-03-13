#include "integrity_detector.h"

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>

#pragma comment(lib, "wintrust.lib")

namespace flutter_neo_shield {

bool IntegrityDetector::Check() {
  return CheckAuthenticode() || CheckImageChecksum();
}

/// Verify Authenticode signature of the running executable.
///
/// WinVerifyTrust is the Windows standard for code signature verification.
/// Returns true (tampered) if the signature is missing, invalid, or
/// the certificate chain is broken.
bool IntegrityDetector::CheckAuthenticode() {
  wchar_t exe_path[MAX_PATH];
  DWORD len = ::GetModuleFileNameW(NULL, exe_path, MAX_PATH);
  if (len == 0 || len >= MAX_PATH) {
    return true;  // Can't determine path — fail-closed
  }

  WINTRUST_FILE_INFO fileInfo = {};
  fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
  fileInfo.pcwszFilePath = exe_path;
  fileInfo.hFile = NULL;
  fileInfo.pgKnownSubject = NULL;

  GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

  WINTRUST_DATA trustData = {};
  trustData.cbStruct = sizeof(WINTRUST_DATA);
  trustData.pPolicyCallbackData = NULL;
  trustData.pSIPClientData = NULL;
  trustData.dwUIChoice = WTD_UI_NONE;
  trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
  trustData.dwUnionChoice = WTD_CHOICE_FILE;
  trustData.pFile = &fileInfo;
  trustData.dwStateAction = WTD_STATEACTION_VERIFY;
  trustData.hWVTStateData = NULL;
  trustData.pwszURLReference = NULL;
  trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

  LONG result = ::WinVerifyTrust(NULL, &policyGUID, &trustData);

  // Clean up state
  trustData.dwStateAction = WTD_STATEACTION_CLOSE;
  ::WinVerifyTrust(NULL, &policyGUID, &trustData);

  // TRUST_E_NOSIGNATURE means unsigned — might be normal during development
  if (result == static_cast<LONG>(TRUST_E_NOSIGNATURE)) {
    #ifdef NDEBUG
    return true;  // Unsigned in release — suspicious
    #else
    return false;  // Normal during development
    #endif
  }

  // Any other failure means tampered or invalid signature
  return result != ERROR_SUCCESS;
}

/// Verify the PE image checksum matches the computed checksum.
///
/// The PE optional header contains a checksum. If the binary has been
/// modified after signing, this checksum will be wrong.
bool IntegrityDetector::CheckImageChecksum() {
  wchar_t exe_path[MAX_PATH];
  if (::GetModuleFileNameW(NULL, exe_path, MAX_PATH) == 0) return false;

  HANDLE file = ::CreateFileW(exe_path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
  if (file == INVALID_HANDLE_VALUE) return false;

  DWORD file_size = ::GetFileSize(file, NULL);
  if (file_size == INVALID_FILE_SIZE) {
    ::CloseHandle(file);
    return false;
  }

  HANDLE mapping = ::CreateFileMappingW(file, NULL, PAGE_READONLY, 0, 0, NULL);
  if (!mapping) {
    ::CloseHandle(file);
    return false;
  }

  void *view = ::MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
  if (!view) {
    ::CloseHandle(mapping);
    ::CloseHandle(file);
    return false;
  }

  // Read PE header checksum
  auto *dos = static_cast<IMAGE_DOS_HEADER *>(view);
  bool tampered = false;

  if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
    auto *nt = reinterpret_cast<IMAGE_NT_HEADERS *>(
        static_cast<BYTE *>(view) + dos->e_lfanew);
    if (nt->Signature == IMAGE_NT_SIGNATURE) {
      DWORD stored_checksum = nt->OptionalHeader.CheckSum;
      // A zero checksum means the binary was not checksummed — common in dev
      if (stored_checksum != 0) {
        // Compute actual checksum
        DWORD computed = 0;
        auto *words = static_cast<WORD *>(view);
        DWORD word_count = file_size / 2;
        for (DWORD i = 0; i < word_count; i++) {
          computed += words[i];
          computed = (computed >> 16) + (computed & 0xFFFF);
        }
        if (file_size % 2) {
          computed += static_cast<BYTE *>(view)[file_size - 1];
          computed = (computed >> 16) + (computed & 0xFFFF);
        }
        computed += file_size;

        if (computed != stored_checksum) {
          tampered = true;
        }
      }
    }
  }

  ::UnmapViewOfFile(view);
  ::CloseHandle(mapping);
  ::CloseHandle(file);
  return tampered;
}

}  // namespace flutter_neo_shield
