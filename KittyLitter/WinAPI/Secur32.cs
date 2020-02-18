using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace KittyLitter.WinAPI
{
    public class Secur32
    {
        #region Function Defintions
        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaConnectUntrusted(
            [Out] out IntPtr LsaHandle
        );

        [DllImport("secur32.dll", SetLastError = true)]
        public static extern int LsaRegisterLogonProcess(
            LSA_STRING_IN LogonProcessName,
            out IntPtr LsaHandle,
            out ulong SecurityMode
        );

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaDeregisterLogonProcess(
            [In] IntPtr LsaHandle
        );

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaLookupAuthenticationPackage(
            [In] IntPtr LsaHandle,
            [In] ref LSA_STRING_IN PackageName,
            [Out] out int AuthenticationPackage
        );

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaCallAuthenticationPackage(
            IntPtr LsaHandle,
            int AuthenticationPackage,
            IntPtr ProtocolSubmitBuffer,
            int SubmitBufferLength,
            out IntPtr ProtocolReturnBuffer,
            out int ReturnBufferLength,
            out int ProtocolStatus
        );

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern uint LsaFreeReturnBuffer(
            IntPtr buffer
        );

        [DllImport("Secur32.dll", SetLastError = false)]
        public static extern uint LsaEnumerateLogonSessions(
            out UInt64 LogonSessionCount,
            out IntPtr LogonSessionList
        );

        [DllImport("Secur32.dll", SetLastError = false)]
        public static extern uint LsaGetLogonSessionData(
            IntPtr luid,
            out IntPtr ppLogonSessionData
        );
        #endregion

        #region Structure Defintions
        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING_IN
        {
            public ushort Length;
            public ushort MaximumLength;
            public string Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING_OUT
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }


        public enum SECURITY_LOGON_TYPE : uint
        {
            Interactive = 2,        // logging on interactively.
            Network,                // logging using a network.
            Batch,                  // logon for a batch process.
            Service,                // logon for a service account.
            Proxy,                  // Not supported.
            Unlock,                 // Tattempt to unlock a workstation.
            NetworkCleartext,       // network logon with cleartext credentials
            NewCredentials,         // caller can clone its current token and specify new credentials for outbound connections
            RemoteInteractive,      // terminal server session that is both remote and interactive
            CachedInteractive,      // attempt to use the cached credentials without going out across the network
            CachedRemoteInteractive,// same as RemoteInteractive, except used internally for auditing purposes
            CachedUnlock            // attempt to unlock a workstation
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_LOGON_SESSION_DATA
        {
            public uint Size;
            public LUID LoginID;
            public LSA_STRING_OUT Username;
            public LSA_STRING_OUT LoginDomain;
            public LSA_STRING_OUT AuthenticationPackage;
            public uint LogonType;
            public uint Session;
            public IntPtr PSiD;
            public ulong LoginTime;
            public LSA_STRING_OUT LogonServer;
            public LSA_STRING_OUT DnsDomainName;
            public LSA_STRING_OUT Upn;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public UInt32 LowPart;
            public Int32 HighPart;

            public LUID(UInt64 value)
            {
                LowPart = (UInt32)(value & 0xffffffffL);
                HighPart = (Int32)(value >> 32);
            }

            public LUID(LUID value)
            {
                LowPart = value.LowPart;
                HighPart = value.HighPart;
            }

            public LUID(string value)
            {
                if (System.Text.RegularExpressions.Regex.IsMatch(value, @"^0x[0-9A-Fa-f]+$"))
                {
                    // if the passed LUID string is of form 0xABC123
                    UInt64 uintVal = Convert.ToUInt64(value, 16);
                    LowPart = (UInt32)(uintVal & 0xffffffffL);
                    HighPart = (Int32)(uintVal >> 32);
                }
                else if (System.Text.RegularExpressions.Regex.IsMatch(value, @"^\d+$"))
                {
                    // if the passed LUID string is a decimal form
                    UInt64 uintVal = UInt64.Parse(value);
                    LowPart = (UInt32)(uintVal & 0xffffffffL);
                    HighPart = (Int32)(uintVal >> 32);
                }
                else
                {
                    ArgumentException argEx = new ArgumentException("Passed LUID string value is not in a hex or decimal form", value);
                    throw argEx;
                }
            }

            public override int GetHashCode()
            {
                UInt64 Value = ((UInt64)this.HighPart << 32) + this.LowPart;
                return Value.GetHashCode();
            }

            public override bool Equals(object obj)
            {
                return obj is LUID && (((ulong)this) == (LUID)obj);
            }

            public byte[] GetBytes()
            {
                byte[] bytes = new byte[8];

                byte[] lowBytes = BitConverter.GetBytes(this.LowPart);
                byte[] highBytes = BitConverter.GetBytes(this.HighPart);

                Array.Copy(lowBytes, 0, bytes, 0, 4);
                Array.Copy(highBytes, 0, bytes, 4, 4);

                return bytes;
            }

            public override string ToString()
            {
                UInt64 Value = ((UInt64)this.HighPart << 32) + this.LowPart;
                return String.Format("0x{0:x}", (ulong)Value);
            }

            public static bool operator ==(LUID x, LUID y)
            {
                return (((ulong)x) == ((ulong)y));
            }

            public static bool operator !=(LUID x, LUID y)
            {
                return (((ulong)x) != ((ulong)y));
            }

            public static implicit operator ulong(LUID luid)
            {
                // enable casting to a ulong
                UInt64 Value = ((UInt64)luid.HighPart << 32);
                return Value + luid.LowPart;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_GROUPS
        {
            public int GroupCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public SID_AND_ATTRIBUTES[] Groups;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_HANDLE
        {
            public IntPtr LowPart;
            public IntPtr HighPart;
        };

        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 35)]
            public LUID_AND_ATTRIBUTES[] Privileges;

            public TOKEN_PRIVILEGES(uint PrivilegeCount = 0, LUID_AND_ATTRIBUTES[] Privileges = null)
            {
                this.PrivilegeCount = PrivilegeCount;
                this.Privileges = Privileges;
            }
        }

        #endregion

        #region Helper Functions
        public static IntPtr LsaRegisterLogonProcessHelper()
        {
            // helper that establishes a connection to the LSA server and verifies that the caller is a logon application
            // used for Kerberos ticket enumeration

            const string logonProcessName = "User32LogonProcess";
            LSA_STRING_IN lsaString;

            lsaString.Length = (ushort)logonProcessName.Length;
            lsaString.MaximumLength = (ushort)(logonProcessName.Length + 1);
            lsaString.Buffer = logonProcessName;

            var ret = LsaRegisterLogonProcess(lsaString, out var lsaHandle, out _);

            return lsaHandle;
        }

        #endregion
    }
}
