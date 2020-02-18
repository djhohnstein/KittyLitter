using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Reflection;
using System.Runtime.InteropServices;

namespace KittyLitter.WinAPI
{
    public class Kernel32
    {
        [Flags]
        internal enum ThreadStatusFlags : UInt32
        {
            STILL_ACTIVE = 0x00000103
        }

        [Flags]
        internal enum ProcessAccessFlags : UInt32
        {
            PROCESS_CREATE_PROCESS = 0x0080,
            PROCESS_CREATE_THREAD = 0x0002,
            PROCESS_DUP_HANDLE = 0x0040,
            PROCESS_QUERY_INFORMATION = 0x0400,
            PROCESS_QUERY_LIMITED_INFORMATION = 0x0200,
            PROCESS_SET_QUOTA = 0x0100,
            PROCESS_SUSPEND_RESUME = 0x0800,
            PROCESS_TERMINATE = 0x0001,
            PROCESS_VM_OPERATION = 0x0008,
            PROCESS_VM_READ = 0x0010,
            PROCESS_VM_WRITE = 0x0020,
            SYNCHRONIZE = 0x00100000,
            PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFFF
        }

        [Flags]
        public enum ProcessCreationFlags : uint
        {
            DEBUG_PROCESS = 0x00000001,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            CREATE_SUSPENDED = 0x00000004,
            DETACHED_PROCESS = 0x00000008,
            CREATE_NEW_CONSOLE = 0x00000010,
            NORMAL_PRIORITY_CLASS = 0x00000020,
            IDLE_PRIORITY_CLASS = 0x00000040,
            HIGH_PRIORITY_CLASS = 0x00000080,
            REALTIME_PRIORITY_CLASS = 0x00000100,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_FORCEDOS = 0x00002000,
            BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
            ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
            INHERIT_PARENT_AFFINITY = 0x00010000,
            INHERIT_CALLER_PRIORITY = 0x00020000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
            PROCESS_MODE_BACKGROUND_END = 0x00200000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NO_WINDOW = 0x08000000,
            PROFILE_USER = 0x10000000,
            PROFILE_KERNEL = 0x20000000,
            PROFILE_SERVER = 0x40000000,
            CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000
        }

        [Flags]
        internal enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        internal enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        // This also works with CharSet.Ansi as long as the calling function uses the same character set.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        // This also works with CharSet.Ansi as long as the calling function uses the same character set.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [DllImport("kernel32.dll")]
        internal static extern bool VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr CreateThread(
           uint ThreadAttributes,
           uint StackSize,
           IntPtr StartFunction,
           IntPtr ThreadParameter,
           uint CreationFlags,
           ref uint ThreadId);

        [DllImport("kernel32.dll")]
        internal static extern int GetProcessId(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool IsWow64Process(
            IntPtr hProcess,
            out bool Wow64Process);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        internal static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            ulong dwSize,
            AllocationType flAllocationType,
            MemoryProtection flProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        internal static extern IntPtr VirtualAllocEx(
           IntPtr hProcess,
           IntPtr lpAddress,
           ulong dwSize,
           AllocationType flAllocationType,
           MemoryProtection flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr WaitForSingleObject(
            IntPtr hHandle,
            UInt32 dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CreateProcessA(
            string lpApplicationName,
            string lpCommandLine,
            SECURITY_ATTRIBUTES lpProcessAttributes,
            SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            ProcessCreationFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CreateProcessA(
            string lpApplicationName,
            string lpCommandLine,
            Advapi32.SECURITY_ATTRIBUTES lpProcessAttributes,
            Advapi32.SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            Advapi32.ProcessCreationFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            Advapi32.STARTUPINFO lpStartupInfo,
            out Advapi32.PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr OpenProcess(
            ProcessAccessFlags dwDesiredAccess,
            bool bInheritHandle,
            int dwProcessId);

        [DllImport("kernel32.dll")]
        internal static extern int GetExitCodeThread(
            IntPtr hThread,
            out int lpExitCode);

        [DllImport("kernel32.dll")]
        internal static extern int GetExitCodeProcess(
            IntPtr hProcess,
            out int lpExitCode);

        [DllImport("kernel32.dll")]
        internal static extern bool CreatePipe(
            out IntPtr hReadPipe,
            out IntPtr hWritePipe,
            SECURITY_ATTRIBUTES lpPipeAttributes,
            uint nSize);

        [DllImport("kernel32.dll")]
        internal static extern bool SetHandleInformation(
            IntPtr hObject,
            uint dwMask,
            uint dwFlags);

        [DllImport("kernel32.dll")]
        internal static extern bool ReadFile(
            IntPtr hFile,
            out byte[] lpBuffer,
            uint nNumberOfBytesToRead,
            ref uint lpNumberOfBytesRead,
            IntPtr lpOverLapped); // I'm not sure you need the overlapped struct

        [DllImport("kernel32.dll")]
        internal static extern bool WriteFile(
            IntPtr hFile,
            byte[] lpBuffer,
            uint nNumberOfBytesToWrite,
            out uint lpNumberOfBytesWritten,
            IntPtr lpOverLapped); // Not sure we need overlapped.

        [DllImport("kernel32.dll")]
        internal static extern int ResumeThread(
            IntPtr hThread);

        [DllImport("kernel32.dll")]
        internal static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            out uint lpNumberOfBytesWritten);
    }
    //class Kernel32
    //{
    //    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    //    public static extern IntPtr CreateMailslot(
    //        string lpName,
    //        uint nMaxMessageSize,
    //        uint lReadTimeout,
    //        IntPtr lpSecurityAttributes);

    //    [DllImport("kernel32.dll")]
    //    public static extern bool GetMailslotInfo(
    //        IntPtr hMailslot,
    //        IntPtr lpMaxMessageSize,
    //        IntPtr lpNextSize,
    //        IntPtr lpMessageCount,
    //        IntPtr lpReadTimeout);

    //    [DllImport("kernel32.dll")]
    //    public static extern bool SetMailslotInfo(
    //        IntPtr hMailslot,
    //        uint lReadTimeout
    //    );
    //}
}
