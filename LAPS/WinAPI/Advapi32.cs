using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;
using LSA_HANDLE = System.IntPtr;
using static KittyLitter.WinAPI.Secur32;

namespace KittyLitter.WinAPI
{
    public class Advapi32
    {

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

        internal enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            internal IntPtr hProcess;
            internal IntPtr hThread;
            internal int dwProcessId;
            internal int dwThreadId;
        }

        [Flags]
        internal enum LOGON_TYPE : UInt32
        {
            LOGON32_LOGON_INTERACTIVE = 2,
            LOGON32_LOGON_NETWORK = 3,
            LOGON32_LOGON_BATCH = 4,
            LOGON32_LOGON_SERVICE = 5,
            LOGON32_LOGON_UNLOCK = 7,
            LOGON32_LOGON_NETWORK_CLEARTEXT = 8,
            LOGON32_LOGON_NEW_CREDENTIALS = 9
        }

        internal enum LOGON_PROVIDER : UInt32
        {
            LOGON32_PROVIDER_DEFAULT = 0,
            LOGON32_PROVIDER_WINNT35 = 1,
            LOGON32_PROVIDER_WINNT40 = 2,
            LOGON32_PROVIDER_WINNT50 = 3,
            LOGON32_PROVIDER_VIRTUAL = 4
        }

        [Flags]
        internal enum STARTF : uint
        {
            STARTF_USESHOWWINDOW = 0x00000001,
            STARTF_USESIZE = 0x00000002,
            STARTF_USEPOSITION = 0x00000004,
            STARTF_USECOUNTCHARS = 0x00000008,
            STARTF_USEFILLATTRIBUTE = 0x00000010,
            STARTF_RUNFULLSCREEN = 0x00000020,  // ignored for non-x86 platforms
            STARTF_FORCEONFEEDBACK = 0x00000040,
            STARTF_FORCEOFFFEEDBACK = 0x00000080,
            STARTF_USESTDHANDLES = 0x00000100,
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        internal struct STARTUPINFO
        {
            internal Int32 cb;
            internal IntPtr lpReserved;
            internal IntPtr lpDesktop;
            internal IntPtr lpTitle;
            internal Int32 dwX;
            internal Int32 dwY;
            internal Int32 dwXSize;
            internal Int32 dwYSize;
            internal Int32 dwXCountChars;
            internal Int32 dwYCountChars;
            internal Int32 dwFillAttribute;
            internal uint dwFlags;
            internal Int16 wShowWindow;
            internal Int16 cbReserved2;
            internal IntPtr lpReserved2;
            internal IntPtr hStdInput;
            internal IntPtr hStdOutput;
            internal IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        #region Function Definitions
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool CreateProcessWithLogonW(
            string lpUsername,
            string lpDomain,
            string lpPassword,
            uint dwLogonFlags,
            string lpApplicationName,
            string lpCommandLine,
            IntPtr dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);


        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal extern static bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            IntPtr lpTokenAttributes,
            uint ImpersonationLevel,
            TOKEN_TYPE TokenType,
            out IntPtr phNewToken);

        [DllImport("advapi32.dll")]
        internal extern static bool LogonUserA(
            string lpszUsername,
            string lpszDomain,
            string lpszPassword,
            LOGON_TYPE dwLogonType,
            LOGON_PROVIDER dwLogonProvider,
            out IntPtr phToken);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool CreateProcessWithTokenW(
            IntPtr hToken,
            IntPtr dwLogonFlags,
            string lpApplicationName,
            string lpCommandLine,
            IntPtr dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool CreateProcessAsUserA(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            SECURITY_ATTRIBUTES lpProcessAttributes,
            SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            Advapi32.ProcessCreationFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            STARTUPINFO lpStartupInfo,
            PROCESS_INFORMATION lpProcessInformation);


        [DllImport("kernel32.dll")]
        public static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern IntPtr GetSidSubAuthorityCount(
            IntPtr pSid
            );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern IntPtr GetSidSubAuthority(
            IntPtr pSid,
            int nSubAuthority);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeName(
            string lpSystemName,
            IntPtr lpLuid,
            StringBuilder lpName,
            ref int cchName);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint I_QueryTagInformation(
            IntPtr Unknown,
            SC_SERVICE_TAG_QUERY_TYPE Type,
            ref SC_SERVICE_TAG_QUERY Query
            );

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool LookupAccountSid(
          string lpSystemName,
          [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
          StringBuilder lpName,
          ref uint cchName,
          StringBuilder ReferencedDomainName,
          ref uint cchReferencedDomainName,
          out SID_NAME_USE peUse);

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        public static extern uint LsaOpenPolicy(
            LSA_UNICODE_STRING[] SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            int AccessMask,
            out IntPtr PolicyHandle
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        public static extern uint LsaEnumerateAccountsWithUserRight(
            LSA_HANDLE PolicyHandle,
            LSA_UNICODE_STRING[] UserRights,
            out IntPtr EnumerationBuffer,
            out int CountReturned
        );

        [DllImport("advapi32")]
        public static extern int LsaNtStatusToWinError(int NTSTATUS);

        [DllImport("advapi32")]
        public static extern int LsaClose(IntPtr PolicyHandle);

        [DllImport("advapi32")]
        public static extern int LsaFreeMemory(IntPtr Buffer);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern int RegOpenKeyEx(
            UIntPtr hKey,
            string subKey,
            uint ulOptions,
            uint samDesired,
            out IntPtr hkResult);

        [DllImport("advapi32.dll", EntryPoint = "GetNamedSecurityInfoW", CharSet = CharSet.Unicode)]
        public static extern int GetNamedSecurityInfo(
            string objectName,
            SE_OBJECT_TYPE objectType,
            System.Security.AccessControl.SecurityInfos securityInfo,
            out IntPtr sidOwner,
            out IntPtr sidGroup,
            out IntPtr dacl,
            out IntPtr sacl,
            out IntPtr securityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(
            IntPtr SecurityDescriptor,
            uint StringSDRevision,
            System.Security.AccessControl.SecurityInfos SecurityInformation,
            out string StringSecurityDescriptor,
            out int StringSecurityDescriptorSize);

        // for GetSystem()
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            UInt32 DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("advapi32.dll")]
        public static extern bool DuplicateToken(
            IntPtr ExistingTokenHandle,
            int SECURITY_IMPERSONATION_LEVEL,
            ref IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(
            IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();

        [DllImport("advapi32.dll", EntryPoint = "CredFree", SetLastError = true)]
        internal static extern void CredFree(
            [In] IntPtr cred);

        [DllImport("advapi32.dll", EntryPoint = "CredEnumerate", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CredEnumerate(
            string filter,
            int flag,
            out int count,
            out IntPtr pCredentials);

        [DllImport("Advapi32", SetLastError = false)]
        public static extern bool IsTextUnicode(
                byte[] buf,
                int len,
                ref IsTextUnicodeFlags opt
            );

        #endregion


        #region Enum Definitions

        public enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
        }

        public enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            TokenIsAppContainer,
            TokenCapabilities,
            TokenAppContainerSid,
            TokenAppContainerNumber,
            TokenUserClaimAttributes,
            TokenDeviceClaimAttributes,
            TokenRestrictedUserClaimAttributes,
            TokenRestrictedDeviceClaimAttributes,
            TokenDeviceGroups,
            TokenRestrictedDeviceGroups,
            TokenSecurityAttributes,
            TokenIsRestricted,
            TokenProcessTrustLevel,
            TokenPrivateNameSpace,
            TokenSingletonAttributes,
            TokenBnoIsolation,
            TokenChildProcessFlags,
            MaxTokenInfoClass,
            TokenIsLessPrivilegedAppContainer,
            TokenIsSandboxed,
            TokenOriginatingProcessTrustLevel
        }

        public enum SC_SERVICE_TAG_QUERY_TYPE
        {
            ServiceNameFromTagInformation = 1,
            ServiceNamesReferencingModuleInformation = 2,
            ServiceNameTagMappingInformation = 3
        }

        public enum SE_OBJECT_TYPE
        {
            SE_UNKNOWN_OBJECT_TYPE = 0,
            SE_FILE_OBJECT,
            SE_SERVICE,
            SE_PRINTER,
            SE_REGISTRY_KEY,
            SE_LMSHARE,
            SE_KERNEL_OBJECT,
            SE_WINDOW_OBJECT,
            SE_DS_OBJECT,
            SE_DS_OBJECT_ALL,
            SE_PROVIDER_DEFINED_OBJECT,
            SE_WMIGUID_OBJECT,
            SE_REGISTRY_WOW64_32KEY
        }


        [Flags]
        public enum LuidAttributes : uint
        {
            DISABLED = 0x00000000,
            SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001,
            SE_PRIVILEGE_ENABLED = 0x00000002,
            SE_PRIVILEGE_REMOVED = 0x00000004,
            SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000
        }


        public enum CredentialType : uint
        {
            None = 0,
            Generic = 1,
            DomainPassword = 2,
            DomainCertificate = 3,
            DomainVisiblePassword = 4,
            GenericCertificate = 5,
            DomainExtended = 6,
            Maximum = 7,
            CredTypeMaximum = Maximum + 1000
        }

        public enum PersistenceType : uint
        {
            Session = 1,
            LocalComputer = 2,
            Enterprise = 3
        }

        // for unicode detection
        [Flags]
        public enum IsTextUnicodeFlags : int
        {
            IS_TEXT_UNICODE_ASCII16 = 0x0001,
            IS_TEXT_UNICODE_REVERSE_ASCII16 = 0x0010,

            IS_TEXT_UNICODE_STATISTICS = 0x0002,
            IS_TEXT_UNICODE_REVERSE_STATISTICS = 0x0020,

            IS_TEXT_UNICODE_CONTROLS = 0x0004,
            IS_TEXT_UNICODE_REVERSE_CONTROLS = 0x0040,

            IS_TEXT_UNICODE_SIGNATURE = 0x0008,
            IS_TEXT_UNICODE_REVERSE_SIGNATURE = 0x0080,

            IS_TEXT_UNICODE_ILLEGAL_CHARS = 0x0100,
            IS_TEXT_UNICODE_ODD_LENGTH = 0x0200,
            IS_TEXT_UNICODE_DBCS_LEADBYTE = 0x0400,
            IS_TEXT_UNICODE_NULL_BYTES = 0x1000,

            IS_TEXT_UNICODE_UNICODE_MASK = 0x000F,
            IS_TEXT_UNICODE_REVERSE_MASK = 0x00F0,
            IS_TEXT_UNICODE_NOT_UNICODE_MASK = 0x0F00,
            IS_TEXT_UNICODE_NOT_ASCII_MASK = 0xF000
        }

        #endregion


        #region Structure Defintions

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public int Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct LSA_UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_ENUMERATION_INFORMATION
        {
            public IntPtr PSid;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SC_SERVICE_TAG_QUERY
        {
            public uint ProcessId;
            public uint ServiceTag;
            public uint Unknown;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct TOKEN_STATISTICS
        {
            public LUID TokenId;
            public LUID AuthenticationId;
            public long ExpirationTime;
            public uint TokenType;
            public uint ImpersonationLevel;
            public uint DynamicCharged;
            public uint DynamicAvailable;
            public uint GroupCount;
            public uint PrivilegeCount;
            public LUID ModifiedId;
        }


        [StructLayout(LayoutKind.Sequential)]
        internal struct CREDENTIAL
        {
            public int Flags;
            public CredentialType Type;
            [MarshalAs(UnmanagedType.LPWStr)] public string TargetName;
            [MarshalAs(UnmanagedType.LPWStr)] public string Comment;
            public long LastWritten;
            public int CredentialBlobSize;
            public IntPtr CredentialBlob;
            public PersistenceType Persist;
            public int AttributeCount;
            public IntPtr Attributes;
            [MarshalAs(UnmanagedType.LPWStr)] public string TargetAlias;
            [MarshalAs(UnmanagedType.LPWStr)] public string UserName;
        }

        #endregion


        #region Helper Functions

        // Based off of code by Lee Christensen(@tifkin_) from https://github.com/Invoke-IR/ACE/blob/master/ACE-Management/PS-ACE/Scripts/ACE_Get-NetworkConnection.ps1#L1046
        public static string GetServiceNameFromTag(uint processId, uint serviceTag)
        {
            var serviceTagQuery = new SC_SERVICE_TAG_QUERY
            {
                ProcessId = processId,
                ServiceTag = serviceTag
            };

            var res = I_QueryTagInformation(IntPtr.Zero, SC_SERVICE_TAG_QUERY_TYPE.ServiceNameFromTagInformation, ref serviceTagQuery);

            return res == Win32Error.Success ? Marshal.PtrToStringUni(serviceTagQuery.Buffer) : null;
        }

        public static string TranslateSid(string sid)
        {
            // adapted from http://www.pinvoke.net/default.aspx/advapi32.LookupAccountSid
            var accountSid = new SecurityIdentifier(sid);
            var accountSidByes = new byte[accountSid.BinaryLength];
            accountSid.GetBinaryForm(accountSidByes, 0);

            var name = new StringBuilder();
            var cchName = (uint)name.Capacity;
            var referencedDomainName = new StringBuilder();
            var cchReferencedDomainName = (uint)referencedDomainName.Capacity;

            var err = 0;
            if (!LookupAccountSid(null, accountSidByes, name, ref cchName, referencedDomainName, ref cchReferencedDomainName, out var sidUse))
            {
                err = Marshal.GetLastWin32Error();
                if (err == Win32Error.InsufficientBuffer)
                {
                    name.EnsureCapacity((int)cchName);
                    referencedDomainName.EnsureCapacity((int)cchReferencedDomainName);
                    err = 0;
                    if (!LookupAccountSid(null, accountSidByes, name, ref cchName, referencedDomainName, ref cchReferencedDomainName, out sidUse))
                        err = Marshal.GetLastWin32Error();
                }
            }

            return err == 0 ? $"{referencedDomainName}\\{name}" : "";
        }

        #endregion
    }
}
