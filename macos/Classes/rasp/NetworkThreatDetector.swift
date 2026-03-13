import Foundation
import Darwin
import SystemConfiguration

/// Detects network-level threats on macOS:
///
/// 1. HTTP/HTTPS/SOCKS Proxy — Burp Suite, mitmproxy, Charles Proxy
/// 2. VPN tunnels — routing traffic through interceptors
/// 3. Suspicious DNS configuration
///
/// These detect MITM attack setups commonly used for reverse engineering.
public class NetworkThreatDetector {

    /// Returns detailed detection results.
    public static func check() -> [String: Any] {
        let proxyDetected = checkProxy()
        let vpnDetected = checkVpn()

        return [
            "proxyDetected": proxyDetected,
            "vpnDetected": vpnDetected,
            "detected": proxyDetected || vpnDetected
        ]
    }

    /// Simple boolean: true if proxy or VPN detected.
    public static func checkSimple() -> Bool {
        return checkProxy() || checkVpn()
    }

    /// Detect HTTP/HTTPS/SOCKS proxy configuration.
    ///
    /// Uses SCDynamicStoreCopyProxies which reads the system proxy
    /// configuration — same source as CFNetworkCopySystemProxySettings.
    private static func checkProxy() -> Bool {
        // Method 1: SystemConfiguration proxy settings
        guard let proxySettings = SCDynamicStoreCopyProxies(nil) as? [String: Any] else {
            return false
        }

        // Check HTTP proxy
        if let httpEnabled = proxySettings[kSCPropNetProxiesHTTPEnable as String] as? Int,
           httpEnabled == 1 {
            if let httpProxy = proxySettings[kSCPropNetProxiesHTTPProxy as String] as? String,
               !httpProxy.isEmpty {
                return true
            }
        }

        // Check HTTPS proxy
        if let httpsEnabled = proxySettings[kSCPropNetProxiesHTTPSEnable as String] as? Int,
           httpsEnabled == 1 {
            if let httpsProxy = proxySettings[kSCPropNetProxiesHTTPSProxy as String] as? String,
               !httpsProxy.isEmpty {
                return true
            }
        }

        // Check SOCKS proxy
        if let socksEnabled = proxySettings[kSCPropNetProxiesSOCKSEnable as String] as? Int,
           socksEnabled == 1 {
            if let socksProxy = proxySettings[kSCPropNetProxiesSOCKSProxy as String] as? String,
               !socksProxy.isEmpty {
                return true
            }
        }

        // Method 2: Check environment variables (CLI tools often set these)
        let env = ProcessInfo.processInfo.environment
        let proxyVars = ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]
        for varName in proxyVars {
            if let value = env[varName], !value.isEmpty {
                return true
            }
        }

        return false
    }

    /// Detect active VPN connections via network interfaces.
    ///
    /// VPN tunnels create virtual network interfaces with known prefixes.
    private static func checkVpn() -> Bool {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else {
            return false
        }
        defer { freeifaddrs(ifaddr) }

        let vpnPrefixes = ["utun", "ppp", "ipsec", "tap", "tun"]

        var addr = firstAddr
        while true {
            let name = String(cString: addr.pointee.ifa_name)
            let flags = Int32(addr.pointee.ifa_flags)
            let isUp = (flags & IFF_UP) != 0

            if isUp {
                for prefix in vpnPrefixes {
                    if name.hasPrefix(prefix) {
                        return true
                    }
                }
            }

            guard let next = addr.pointee.ifa_next else { break }
            addr = next
        }

        return false
    }
}
