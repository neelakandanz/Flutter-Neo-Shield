import Foundation
import IOKit

/// Detects if the macOS app is running inside a virtual machine.
///
/// Checks multiple heuristics:
/// 1. sysctl hw.model for known VM identifiers
/// 2. IOKit registry for VM-specific devices
/// 3. System profiler hardware info
/// 4. Known VM MAC address prefixes
public class VMDetector {
    public static func check() -> Bool {
        return checkHardwareModel() || checkIOKit() || checkMACAddress()
    }

    /// Check sysctl hw.model for VM signatures.
    ///
    /// VMs report model strings like "VMware", "VirtualBox", "Parallels", etc.
    private static func checkHardwareModel() -> Bool {
        var size: Int = 0
        sysctlbyname("hw.model", nil, &size, nil, 0)
        guard size > 0 else { return false }

        var model = [CChar](repeating: 0, count: size)
        sysctlbyname("hw.model", &model, &size, nil, 0)
        let modelStr = String(cString: model).lowercased()

        let vmIndicators = [
            "vmware", "virtualbox", "parallels", "qemu",
            "virtual", "bhyve", "xen", "hyperv"
        ]

        for indicator in vmIndicators {
            if modelStr.contains(indicator) {
                return true
            }
        }

        // Also check manufacturer via sysctl
        var mfgSize: Int = 0
        sysctlbyname("machdep.cpu.brand_string", nil, &mfgSize, nil, 0)
        if mfgSize > 0 {
            var brand = [CChar](repeating: 0, count: mfgSize)
            sysctlbyname("machdep.cpu.brand_string", &brand, &mfgSize, nil, 0)
            let brandStr = String(cString: brand).lowercased()

            if brandStr.contains("qemu") || brandStr.contains("virtual") {
                return true
            }
        }

        return false
    }

    /// IOKit main port — uses the modern API on macOS 12+ and the deprecated one on older.
    private static var ioMainPort: mach_port_t {
        if #available(macOS 12.0, *) {
            return kIOMainPortDefault
        } else {
            // Silence deprecation warning — needed for macOS < 12 support
            let port: mach_port_t = 0 // kIOMasterPortDefault is always 0
            return port
        }
    }

    /// Check IOKit registry for VM-specific hardware.
    ///
    /// VMs register IOService entries with identifiable names.
    private static func checkIOKit() -> Bool {
        let vmServiceNames = [
            "VMwareGfx",
            "VBoxGuest",
            "VBoxSF",
            "paborServices",  // Parallels
            "prl_hypervisor",
        ]

        for name in vmServiceNames {
            let service = IOServiceGetMatchingService(
                ioMainPort,
                IOServiceMatching(name)
            )
            if service != IO_OBJECT_NULL {
                IOObjectRelease(service)
                return true
            }
        }

        // Check for generic VM display adapters
        let matchDict = IOServiceMatching("IOPCIDevice")
        var iterator: io_iterator_t = 0
        let result = IOServiceGetMatchingServices(ioMainPort, matchDict, &iterator)

        if result == KERN_SUCCESS {
            defer { IOObjectRelease(iterator) }
            var service = IOIteratorNext(iterator)
            while service != IO_OBJECT_NULL {
                if let vendorID = IORegistryEntryCreateCFProperty(
                    service, "vendor-id" as CFString, kCFAllocatorDefault, 0
                )?.takeRetainedValue() as? Data {
                    // VMware vendor ID: 0x15AD, VirtualBox: 0x80EE
                    if vendorID.count >= 2 {
                        let vid = UInt16(vendorID[0]) | (UInt16(vendorID[1]) << 8)
                        if vid == 0x15AD || vid == 0x80EE {
                            IOObjectRelease(service)
                            return true
                        }
                    }
                }
                IOObjectRelease(service)
                service = IOIteratorNext(iterator)
            }
        }

        return false
    }

    /// Check network interface MAC addresses for known VM prefixes.
    ///
    /// VMware: 00:0C:29, 00:50:56, 00:05:69
    /// VirtualBox: 08:00:27
    /// Parallels: 00:1C:42
    /// QEMU/KVM: 52:54:00
    private static func checkMACAddress() -> Bool {
        let vmMACPrefixes = [
            "00:0c:29", "00:50:56", "00:05:69",  // VMware
            "08:00:27",                            // VirtualBox
            "00:1c:42",                            // Parallels
            "52:54:00",                            // QEMU/KVM
        ]

        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else {
            return false
        }
        defer { freeifaddrs(ifaddr) }

        var addr = firstAddr
        while true {
            let family = addr.pointee.ifa_addr.pointee.sa_family
            if family == UInt8(AF_LINK) {
                let sdl = unsafeBitCast(addr.pointee.ifa_addr, to: UnsafeMutablePointer<sockaddr_dl>.self)
                let nlen = Int(sdl.pointee.sdl_nlen)
                let alen = Int(sdl.pointee.sdl_alen)

                if alen == 6 {
                    var macBytes = [UInt8](repeating: 0, count: 6)
                    withUnsafePointer(to: &sdl.pointee.sdl_data) { ptr in
                        ptr.withMemoryRebound(to: UInt8.self, capacity: nlen + alen) { bytes in
                            for i in 0..<6 {
                                macBytes[i] = bytes[nlen + i]
                            }
                        }
                    }
                    let macStr = macBytes.map { String(format: "%02x", $0) }.joined(separator: ":")
                    let prefix = macBytes[0..<3].map { String(format: "%02x", $0) }.joined(separator: ":")

                    for vmPrefix in vmMACPrefixes {
                        if prefix == vmPrefix {
                            return true
                        }
                    }
                    _ = macStr // silence unused warning
                }
            }

            guard let next = addr.pointee.ifa_next else { break }
            addr = next
        }

        return false
    }
}
