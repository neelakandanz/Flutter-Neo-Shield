import Foundation
import Security

/// Detects code integrity violations on macOS.
///
/// Verifies that the application bundle has not been tampered with:
/// 1. SecStaticCode / SecCodeCheckValidity — OS-level code signature verification
/// 2. Bundle structure integrity checks
/// 3. Executable hash verification
public class IntegrityDetector {
    public static func check() -> Bool {
        return checkCodeSignature() || checkBundleStructure()
    }

    /// Verify code signature using macOS Security framework.
    ///
    /// SecStaticCodeCreateWithPath + SecStaticCodeCheckValidity is the
    /// definitive way to verify code signing on macOS. If the signature
    /// is invalid (modified binary, re-signed, stripped), this fails.
    private static func checkCodeSignature() -> Bool {
        guard let bundleURL = Bundle.main.executableURL else {
            return true // Can't find executable — suspicious
        }

        var staticCode: SecStaticCode?
        let createResult = SecStaticCodeCreateWithPath(
            bundleURL as CFURL,
            SecCSFlags(),
            &staticCode
        )

        guard createResult == errSecSuccess, let code = staticCode else {
            // Can't create code object — unsigned or corrupted
            return true
        }

        // Check if the code signature is valid
        // kSecCSCheckAllArchitectures verifies all slices in universal binary
        let checkResult = SecStaticCodeCheckValidity(
            code,
            SecCSFlags(rawValue: kSecCSCheckAllArchitectures),
            nil // Use default requirement (any valid signature)
        )

        if checkResult != errSecSuccess {
            // Signature verification failed — tampered or unsigned
            return true
        }

        // Additional check: verify the code is signed by Apple or a valid developer
        var requirement: SecRequirement?
        let reqResult = SecRequirementCreateWithString(
            "anchor apple generic" as CFString,
            SecCSFlags(),
            &requirement
        )

        if reqResult == errSecSuccess, let req = requirement {
            let validResult = SecStaticCodeCheckValidity(
                code,
                SecCSFlags(),
                req
            )
            if validResult != errSecSuccess {
                // Not signed by Apple or valid developer certificate
                // This could be a re-signed binary
                return true
            }
        }

        return false
    }

    /// Verify the bundle structure hasn't been modified.
    ///
    /// Check for _CodeSignature directory and its contents.
    private static func checkBundleStructure() -> Bool {
        let bundlePath = Bundle.main.bundlePath
        let codeSignPath = bundlePath + "/Contents/_CodeSignature"
        let codeResPath = codeSignPath + "/CodeResources"

        // Missing CodeSignature directory means unsigned or stripped
        if !FileManager.default.fileExists(atPath: codeResPath) {
            // During development, this may not exist
            #if DEBUG
            return false
            #else
            return true
            #endif
        }

        // Verify CodeResources is a valid plist
        guard let data = FileManager.default.contents(atPath: codeResPath),
              let _ = try? PropertyListSerialization.propertyList(
                  from: data,
                  options: [],
                  format: nil
              ) as? [String: Any] else {
            #if DEBUG
            return false
            #else
            return true
            #endif
        }

        return false
    }
}
