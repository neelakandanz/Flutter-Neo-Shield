import Foundation

/// Detects if a debugger is attached to the current process on macOS.
///
/// Uses sysctl to read the P_TRACED flag from the kernel process info.
/// This is the same mechanism as iOS but without UIKit dependencies.
public class DebuggerDetector {
    public static func check() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        if result != 0 {
            // sysctl failed — fail-closed
            return true
        }
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }
}
