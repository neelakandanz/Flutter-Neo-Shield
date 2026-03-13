#include "signature_detector.h"

#include <windows.h>
#include <wintrust.h>
#include <wincrypt.h>
#include <softpub.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace flutter_neo_shield {

bool SignatureDetector::Check() {
  return CheckAuthenticodeSignature() || CheckCertificateChain();
}

/// Verify Authenticode signature is present and valid.
///
/// This is the primary Windows mechanism for detecting re-signed or
/// tampered executables. A properly signed app will pass; a re-signed
/// app will fail if the certificate doesn't chain to a trusted root.
bool SignatureDetector::CheckAuthenticodeSignature() {
  wchar_t exe_path[MAX_PATH];
  DWORD len = ::GetModuleFileNameW(NULL, exe_path, MAX_PATH);
  if (len == 0 || len >= MAX_PATH) return true;

  WINTRUST_FILE_INFO fileInfo = {};
  fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
  fileInfo.pcwszFilePath = exe_path;

  GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

  WINTRUST_DATA trustData = {};
  trustData.cbStruct = sizeof(WINTRUST_DATA);
  trustData.dwUIChoice = WTD_UI_NONE;
  trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
  trustData.dwUnionChoice = WTD_CHOICE_FILE;
  trustData.pFile = &fileInfo;
  trustData.dwStateAction = WTD_STATEACTION_VERIFY;
  trustData.dwProvFlags = WTD_SAFER_FLAG;

  LONG result = ::WinVerifyTrust(NULL, &policyGUID, &trustData);

  // Clean up
  trustData.dwStateAction = WTD_STATEACTION_CLOSE;
  ::WinVerifyTrust(NULL, &policyGUID, &trustData);

  if (result == static_cast<LONG>(TRUST_E_NOSIGNATURE)) {
    #ifdef NDEBUG
    return true;  // Unsigned in release
    #else
    return false;
    #endif
  }

  return result != ERROR_SUCCESS;
}

/// Verify the certificate chain is valid and trusted.
///
/// Extracts the signing certificate from the executable and validates
/// the full certificate chain. Detects self-signed re-signing certificates.
bool SignatureDetector::CheckCertificateChain() {
  wchar_t exe_path[MAX_PATH];
  DWORD len = ::GetModuleFileNameW(NULL, exe_path, MAX_PATH);
  if (len == 0 || len >= MAX_PATH) return false;

  // Query the embedded signature
  DWORD encoding, content_type, format_type;
  HCERTSTORE store = NULL;
  HCRYPTMSG msg = NULL;

  BOOL success = ::CryptQueryObject(
      CERT_QUERY_OBJECT_FILE,
      exe_path,
      CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
      CERT_QUERY_FORMAT_FLAG_BINARY,
      0,
      &encoding,
      &content_type,
      &format_type,
      &store,
      &msg,
      NULL);

  if (!success || !store) {
    if (msg) ::CryptMsgClose(msg);
    if (store) ::CertCloseStore(store, 0);
    return false;  // No embedded signature — handled by CheckAuthenticodeSignature
  }

  // Get the signer certificate
  PCCERT_CONTEXT cert = ::CertEnumCertificatesInStore(store, NULL);
  bool tampered = false;

  if (cert) {
    // Check if the certificate is self-signed
    // Self-signed certs where issuer == subject are suspicious for production
    if (::CertCompareCertificateName(
            X509_ASN_ENCODING,
            &cert->pCertInfo->Issuer,
            &cert->pCertInfo->Subject)) {
      // Self-signed certificate — may be re-signed
      #ifdef NDEBUG
      tampered = true;
      #endif
    }

    // Verify the certificate chain
    CERT_CHAIN_PARA chainPara = {};
    chainPara.cbSize = sizeof(CERT_CHAIN_PARA);
    PCCERT_CHAIN_CONTEXT chainContext = NULL;

    if (::CertGetCertificateChain(
            NULL, cert, NULL, store, &chainPara, 0, NULL, &chainContext)) {
      // Check chain trust status
      if (chainContext->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR) {
        tampered = true;
      }
      ::CertFreeCertificateChain(chainContext);
    }

    ::CertFreeCertificateContext(cert);
  }

  if (msg) ::CryptMsgClose(msg);
  if (store) ::CertCloseStore(store, 0);

  return tampered;
}

}  // namespace flutter_neo_shield
