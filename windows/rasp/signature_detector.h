#ifndef FLUTTER_NEO_SHIELD_SIGNATURE_DETECTOR_H_
#define FLUTTER_NEO_SHIELD_SIGNATURE_DETECTOR_H_

namespace flutter_neo_shield {

/// Detects code signature tampering on Windows.
///
/// Uses Authenticode and certificate APIs:
/// 1. WinVerifyTrust for signature validation
/// 2. Certificate chain verification
/// 3. Signer information extraction and validation
class SignatureDetector {
 public:
  static bool Check();

 private:
  static bool CheckAuthenticodeSignature();
  static bool CheckCertificateChain();
};

}  // namespace flutter_neo_shield

#endif  // FLUTTER_NEO_SHIELD_SIGNATURE_DETECTOR_H_
