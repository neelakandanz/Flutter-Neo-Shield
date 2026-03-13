import Foundation
import Security

/// Detects code signature tampering on macOS.
///
/// Uses the macOS Security framework for definitive signature verification:
/// 1. SecStaticCode validation — verifies the code signature is intact
/// 2. Code signing requirement checks — verifies signing identity
/// 3. DYLD environment injection detection
/// 4. Entitlement anomaly detection
///
/// This is separate from IntegrityDetector which checks bundle structure.
/// SignatureDetector focuses specifically on the cryptographic signature.
public class SignatureDetector {

    /// Returns true if signature anomalies are detected.
    public static func check() -> Bool {
        return checkCodeSigningIdentity() ||
               checkDYLDEnvironment() ||
               checkEntitlements() ||
               checkReSignIndicators()
    }

    /// Verify the code signing identity using SecCode (running process).
    ///
    /// Gets the running process code reference, converts to static code,
    /// then validates the signature. Catches runtime code modifications.
    private static func checkCodeSigningIdentity() -> Bool {
        var code: SecCode?
        let selfResult = SecCodeCopySelf(SecCSFlags(), &code)

        guard selfResult == errSecSuccess, let selfCode = code else {
            return true
        }

        // Validate running code signature
        let validResult = SecCodeCheckValidity(
            selfCode,
            SecCSFlags(),
            nil
        )

        if validResult != errSecSuccess {
            return true
        }

        // Convert to static code for signing information
        var staticCode: SecStaticCode?
        let staticResult = SecCodeCopyStaticCode(selfCode, SecCSFlags(), &staticCode)
        guard staticResult == errSecSuccess, let scode = staticCode else {
            return false
        }

        // Check signing info for anomalies
        var info: CFDictionary?
        let infoResult = SecCodeCopySigningInformation(
            scode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &info
        )

        if infoResult == errSecSuccess, let signingInfo = info as? [String: Any] {
            // Check if ad-hoc signed (no real identity)
            if let flags = signingInfo[kSecCodeInfoFlags as String] as? UInt32 {
                // kSecCodeSignatureAdhoc = 0x0002
                if (flags & 0x0002) != 0 {
                    #if !DEBUG
                    return true // Ad-hoc signed in release — suspicious
                    #endif
                }
            }
        }

        return false
    }

    /// Check for DYLD injection environment variables.
    private static func checkDYLDEnvironment() -> Bool {
        let env = ProcessInfo.processInfo.environment
        let dangerousVars = [
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "DYLD_FRAMEWORK_PATH",
            "DYLD_FALLBACK_LIBRARY_PATH",
            "DYLD_VERSIONED_LIBRARY_PATH",
            "DYLD_VERSIONED_FRAMEWORK_PATH"
        ]

        for varName in dangerousVars {
            if env[varName] != nil {
                return true
            }
        }

        return false
    }

    /// Check for suspicious entitlements.
    ///
    /// Legitimately signed apps should not have debugging entitlements
    /// in production builds.
    private static func checkEntitlements() -> Bool {
        var code: SecCode?
        let selfResult = SecCodeCopySelf(SecCSFlags(), &code)

        guard selfResult == errSecSuccess, let selfCode = code else {
            return false
        }

        // Convert to static code for signing information
        var staticCode: SecStaticCode?
        let staticResult = SecCodeCopyStaticCode(selfCode, SecCSFlags(), &staticCode)
        guard staticResult == errSecSuccess, let scode = staticCode else {
            return false
        }

        var info: CFDictionary?
        let infoResult = SecCodeCopySigningInformation(
            scode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &info
        )

        if infoResult == errSecSuccess, let signingInfo = info as? [String: Any] {
            // Check for get-task-allow entitlement (allows debugging)
            if let entitlements = signingInfo[kSecCodeInfoEntitlementsDict as String] as? [String: Any] {
                if let getTaskAllow = entitlements["com.apple.security.get-task-allow"] as? Bool,
                   getTaskAllow {
                    #if !DEBUG
                    return true // Debug entitlement in release — re-signed
                    #endif
                }
            }
        }

        return false
    }

    /// Check for indicators of re-signing.
    ///
    /// Tools like codesign can re-sign an app with a different identity.
    /// We check for common artifacts left by re-signing tools.
    private static func checkReSignIndicators() -> Bool {
        let bundlePath = Bundle.main.bundlePath

        // Check for multiple CodeSignature directories (artifact of re-signing)
        let codeSignPath = bundlePath + "/Contents/_CodeSignature"
        if let contents = try? FileManager.default.contentsOfDirectory(atPath: codeSignPath) {
            // A normal app has exactly CodeResources
            // Re-signed apps sometimes leave extra files
            let expectedFiles = Set(["CodeResources"])
            let actualFiles = Set(contents)
            if !actualFiles.isSubset(of: expectedFiles) {
                return true
            }
        }

        return false
    }
}
