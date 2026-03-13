import Foundation
import Darwin
import MachO

// ptrace is not directly available in Swift; declare from C
// PT_DENY_ATTACH = 31
@_silgen_name("ptrace")
private func swift_ptrace(_ request: CInt, _ pid: pid_t, _ addr: UnsafeMutableRawPointer?, _ data: CInt) -> CInt

/// Native-level debugger detection for macOS.
///
/// Goes beyond DebuggerDetector by using:
/// 1. PT_DENY_ATTACH — prevents debugger attachment entirely
/// 2. sysctl P_TRACED — checks if currently being traced
/// 3. Exception port check — debuggers register Mach exception ports
/// 4. Parent process check — detects launch from debugger (lldb, gdb)
/// 5. Timing anomaly — debugger single-stepping causes delays
public class NativeDebugDetector {

    /// Runs all native-level debug detection checks.
    public static func check() -> Bool {
        return checkSysctl() ||
               checkExceptionPorts() ||
               checkParentProcess() ||
               checkTimingAnomaly()
    }

    /// Calls PT_DENY_ATTACH to prevent future debugger attachment.
    ///
    /// One-way operation: any subsequent lldb/gdb attach will SEGFAULT.
    /// Call early in app startup for maximum protection.
    public static func denyDebuggerAttachment() -> Bool {
        let PT_DENY_ATTACH: CInt = 31
        let result = swift_ptrace(PT_DENY_ATTACH, 0, nil, 0)
        return result == 0
    }

    /// Check P_TRACED flag via sysctl.
    private static func checkSysctl() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        if result != 0 {
            return false
        }
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }

    /// Check for debugger via Mach exception ports.
    ///
    /// Debuggers register exception ports to receive signals.
    /// Non-standard exception ports indicate debugger attachment.
    private static func checkExceptionPorts() -> Bool {
        var count: mach_msg_type_number_t = 0
        let excTypesCount = Int(EXC_TYPES_COUNT)
        var masks = [exception_mask_t](repeating: 0, count: excTypesCount)
        var ports = [mach_port_t](repeating: 0, count: excTypesCount)
        var behaviors = [exception_behavior_t](repeating: 0, count: excTypesCount)
        var flavors = [thread_state_flavor_t](repeating: 0, count: excTypesCount)

        let excMaskAll: exception_mask_t = exception_mask_t(
            EXC_MASK_BAD_ACCESS |
            EXC_MASK_BAD_INSTRUCTION |
            EXC_MASK_ARITHMETIC |
            EXC_MASK_EMULATION |
            EXC_MASK_SOFTWARE |
            EXC_MASK_BREAKPOINT |
            EXC_MASK_SYSCALL |
            EXC_MASK_MACH_SYSCALL |
            EXC_MASK_RPC_ALERT |
            EXC_MASK_MACHINE
        )

        let result = withUnsafeMutablePointer(to: &count) { countPtr in
            task_get_exception_ports(
                mach_task_self_,
                excMaskAll,
                &masks,
                countPtr,
                &ports,
                &behaviors,
                &flavors
            )
        }

        if result != KERN_SUCCESS {
            return false
        }

        for i in 0..<Int(count) {
            if ports[i] != 0 && ports[i] != mach_port_t(MACH_PORT_NULL) {
                return true
            }
        }

        return false
    }

    /// Check if the parent process is a debugger.
    ///
    /// When launched from lldb/gdb, the parent process is the debugger.
    /// Normal launch: parent is launchd (pid 1) or the Finder/Dock.
    private static func checkParentProcess() -> Bool {
        let ppid = getppid()

        // Get parent process name via sysctl
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, ppid]
        var size = MemoryLayout<kinfo_proc>.stride
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        if result != 0 {
            return false
        }

        let parentName = withUnsafePointer(to: &info.kp_proc.p_comm) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXCOMLEN)) { cStr in
                String(cString: cStr)
            }
        }.lowercased()

        let debuggerNames = [
            "lldb",
            "gdb",
            "debugserver",
            "dtrace",
            "dtruss",
            "strace",
            "ltrace",
            "processexp",  // Process Explorer
        ]

        for name in debuggerNames {
            if parentName.contains(name) {
                return true
            }
        }

        return false
    }

    /// Timing-based detection.
    ///
    /// Single-stepping through code in a debugger causes measurable delays
    /// in tight loops that normally complete in microseconds.
    private static func checkTimingAnomaly() -> Bool {
        let start = CFAbsoluteTimeGetCurrent()
        var sum: Int64 = 0
        for i in 0..<10000 {
            sum += Int64(i)
        }
        let elapsed = CFAbsoluteTimeGetCurrent() - start
        _ = sum

        // 500ms threshold — normal execution < 5ms
        return elapsed > 0.5
    }
}
