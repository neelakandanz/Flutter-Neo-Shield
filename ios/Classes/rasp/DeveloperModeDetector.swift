import Foundation

/// Detects whether Developer Mode is enabled on the device.
///
/// **iOS 16+:** Apple introduced a user-facing "Developer Mode" toggle
/// (Settings → Privacy & Security → Developer Mode). When enabled it
/// allows sideloading of apps and attachment of debuggers.
///
/// Detection heuristics:
/// 1. Check for the `/Developer` mount path (developer disk image).
/// 2. Check for developer-related files and directories.
/// 3. On iOS 16+, check through the Security framework if available.
///
/// **iOS < 16:** Developer Mode did not exist as a user-facing setting.
/// Returns `false` on these versions.
class DeveloperModeDetector: NSObject {

    static func check() -> Bool {
        // On iOS < 16, Developer Mode toggle does not exist.
        if #available(iOS 16.0, *) {
            return checkDeveloperModeEnabled()
        }
        return false
    }

    @available(iOS 16.0, *)
    private static func checkDeveloperModeEnabled() -> Bool {
        // Heuristic 1: Check for /Developer mount path
        // When a device has Developer Mode enabled AND is paired with Xcode,
        // a Developer disk image may be mounted.
        let developerPaths = [
            "/Developer",
            "/Library/Developer",
            "/usr/lib/libMobileGestalt.dylib"
        ]

        let fileManager = FileManager.default
        for path in developerPaths {
            if fileManager.fileExists(atPath: path) {
                return true
            }
        }

        // Heuristic 2: Check for DeveloperDiskImage signature files
        let signaturePaths = [
            "/Developer/Library",
            "/Developer/usr"
        ]

        for path in signaturePaths {
            var isDir: ObjCBool = false
            if fileManager.fileExists(atPath: path, isDirectory: &isDir), isDir.boolValue {
                return true
            }
        }

        // Heuristic 3: Check if we can call developer-specific APIs
        // The presence of certain developer frameworks loaded at runtime
        // indicates Developer Mode is enabled.
        if let _ = dlopen("/Developer/Library/PrivateFrameworks/DTDDISupport.framework/DTDDISupport", RTLD_LAZY) {
            return true
        }

        return false
    }
}
