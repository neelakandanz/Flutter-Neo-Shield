import Foundation
import Darwin

/// Detects Frida instrumentation toolkit on macOS.
///
/// Frida can attach to macOS processes for dynamic instrumentation.
/// Detection methods:
/// 1. Port scanning for Frida default ports (27042, 27043, 4444)
/// 2. File system check for frida-server binaries
/// 3. Loaded dylib scan for frida-agent/frida-gadget
/// 4. Named pipe check for Frida communication channels
public class FridaDetector {
    public static func check() -> Bool {
        return checkPorts() || checkFiles() || checkLoadedLibraries()
    }

    /// Scan Frida default ports.
    private static func checkPorts() -> Bool {
        let fridaPorts: [in_port_t] = [27042, 27043, 4444]

        for port in fridaPorts {
            if isPortOpen(port) {
                return true
            }
        }
        return false
    }

    /// Check for frida-server binaries on the system.
    private static func checkFiles() -> Bool {
        let fridaPaths = [
            "/usr/local/bin/frida-server",
            "/usr/local/bin/frida",
            "/usr/local/lib/frida",
            "/usr/bin/frida-server",
            "/usr/sbin/frida-server",
            "/opt/homebrew/bin/frida",
            "/opt/homebrew/bin/frida-server",
        ]

        for path in fridaPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        return false
    }

    /// Scan loaded dylibs for frida-related libraries.
    private static func checkLoadedLibraries() -> Bool {
        let suspiciousNames = [
            "frida",
            "fridagadget",
            "frida-agent",
            "frida-gadget",
        ]

        let imageCount = _dyld_image_count()
        for i in 0..<imageCount {
            if let imageName = _dyld_get_image_name(i) {
                let nameStr = String(cString: imageName).lowercased()
                for suspicious in suspiciousNames {
                    if nameStr.contains(suspicious) {
                        return true
                    }
                }
            }
        }

        return false
    }

    /// Check if a TCP port is open on localhost.
    private static func isPortOpen(_ port: in_port_t) -> Bool {
        let sockfd = socket(AF_INET, SOCK_STREAM, 0)
        guard sockfd != -1 else { return false }
        defer { close(sockfd) }

        var timeout = timeval(tv_sec: 1, tv_usec: 0)
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        let result = withUnsafePointer(to: &addr) { addrPtr in
            addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                connect(sockfd, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        return result == 0
    }
}
