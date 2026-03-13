#include "native_debug_detector.h"

#include <windows.h>
#include <winternl.h>

// NtQueryInformationProcess is not in the standard headers
typedef NTSTATUS(NTAPI *NtQueryInformationProcessFn)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

namespace flutter_neo_shield {

bool NativeDebugDetector::Check() {
  return CheckDebugPort() ||
         CheckDebugObjectHandle() ||
         CheckHardwareBreakpoints() ||
         CheckTimingAnomaly();
}

/// Check ProcessDebugPort via NtQueryInformationProcess.
///
/// When a debugger is attached, the debug port is non-zero.
/// This is harder to bypass than IsDebuggerPresent because it
/// queries the kernel directly.
bool NativeDebugDetector::CheckDebugPort() {
  HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
  if (!ntdll) return false;

  auto NtQueryInformationProcess =
      reinterpret_cast<NtQueryInformationProcessFn>(
          ::GetProcAddress(ntdll, "NtQueryInformationProcess"));
  if (!NtQueryInformationProcess) return false;

  // ProcessDebugPort = 7
  DWORD_PTR debug_port = 0;
  NTSTATUS status = NtQueryInformationProcess(
      ::GetCurrentProcess(),
      static_cast<PROCESSINFOCLASS>(7),  // ProcessDebugPort
      &debug_port,
      sizeof(debug_port),
      NULL);

  if (NT_SUCCESS(status) && debug_port != 0) {
    return true;
  }

  return false;
}

/// Check ProcessDebugObjectHandle.
///
/// A debug object handle is created when a debugger attaches.
/// ProcessDebugObjectHandle = 0x1E (30)
bool NativeDebugDetector::CheckDebugObjectHandle() {
  HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
  if (!ntdll) return false;

  auto NtQueryInformationProcess =
      reinterpret_cast<NtQueryInformationProcessFn>(
          ::GetProcAddress(ntdll, "NtQueryInformationProcess"));
  if (!NtQueryInformationProcess) return false;

  HANDLE debug_object = NULL;
  NTSTATUS status = NtQueryInformationProcess(
      ::GetCurrentProcess(),
      static_cast<PROCESSINFOCLASS>(30),  // ProcessDebugObjectHandle
      &debug_object,
      sizeof(debug_object),
      NULL);

  // If successful, a debug object exists = debugger attached
  if (NT_SUCCESS(status)) {
    return true;
  }

  return false;
}

/// Check hardware breakpoints via debug registers.
///
/// Debuggers use DR0-DR3 for hardware breakpoints. If any are set,
/// a debugger is likely controlling execution.
bool NativeDebugDetector::CheckHardwareBreakpoints() {
  CONTEXT ctx = {};
  ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

  if (::GetThreadContext(::GetCurrentThread(), &ctx)) {
    // DR0-DR3 are hardware breakpoint addresses
    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
      return true;
    }
  }

  return false;
}

/// Timing-based detection.
///
/// Single-stepping in a debugger causes measurable delays.
/// A tight loop that runs in < 1ms normally will take much longer
/// when debugger is stepping through.
bool NativeDebugDetector::CheckTimingAnomaly() {
  LARGE_INTEGER freq, start, end;
  ::QueryPerformanceFrequency(&freq);
  ::QueryPerformanceCounter(&start);

  volatile int sum = 0;
  for (int i = 0; i < 10000; i++) {
    sum += i;
  }

  ::QueryPerformanceCounter(&end);

  double elapsed_ms = static_cast<double>(end.QuadPart - start.QuadPart) *
                      1000.0 / static_cast<double>(freq.QuadPart);

  // 500ms threshold — normal execution < 5ms
  return elapsed_ms > 500.0;
}

}  // namespace flutter_neo_shield
