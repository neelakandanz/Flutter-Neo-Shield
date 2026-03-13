import Foundation
import MachO

/// Detects code injection and hooking frameworks on macOS.
///
/// Scans loaded dynamic libraries for known injection/hooking tools:
/// 1. DYLD_INSERT_LIBRARIES environment variable (primary injection vector)
/// 2. Loaded dylib scan via _dyld_image_count / _dyld_get_image_name
/// 3. Suspicious library names associated with hooking frameworks
public class HookDetector {
    public static func check() -> Bool {
        return checkDYLDEnvironment() || checkLoadedDylibs()
    }

    /// Check for DYLD injection environment variables.
    ///
    /// DYLD_INSERT_LIBRARIES is the primary mechanism for injecting
    /// code into macOS processes. Legitimate apps should never have this set.
    private static func checkDYLDEnvironment() -> Bool {
        let env = ProcessInfo.processInfo.environment

        if env["DYLD_INSERT_LIBRARIES"] != nil {
            return true
        }
        if env["DYLD_LIBRARY_PATH"] != nil {
            return true
        }
        if env["DYLD_FRAMEWORK_PATH"] != nil {
            return true
        }

        return false
    }

    /// Scan all loaded dynamic libraries for suspicious names.
    ///
    /// Hooking frameworks inject dylibs that can be detected by name.
    private static func checkLoadedDylibs() -> Bool {
        let suspiciousLibraries = [
            "substrate",
            "cycript",
            "frida",
            "fridagadget",
            "sslkillswitch",
            "sslkillswitch2",
            "mobilesubstrate",
            "substrateinserter",
            "substrateloader",
            "substratebootstrap",
            "libcycript",
            "substitute",
            "shadow",
            "liberty",
            "inject",
            "hook",
            "interpose",
            "fishhook",
            "mitmproxy",
            "charlesproxy",
        ]

        let imageCount = _dyld_image_count()
        for i in 0..<imageCount {
            if let imageName = _dyld_get_image_name(i) {
                let nameStr = String(cString: imageName).lowercased()
                for suspicious in suspiciousLibraries {
                    if nameStr.contains(suspicious) {
                        return true
                    }
                }
            }
        }

        return false
    }
}
