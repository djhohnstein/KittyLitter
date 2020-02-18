using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using KittyLitter.WinAPI;
using System.IO.Pipes;
using System.Security.AccessControl;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using KittyLitter.WinAPI;

namespace KittyLitter.Safety
{
    public class SacrificialProcess
    {
        internal IntPtr hProcess;
        internal IntPtr hThread;
        public int PID;
        public int ExitCode;

        /// <summary>
        /// Resume the thread specified by this class' hThread attribute.
        /// If the process started suspended, this is the main thread of the
        /// created process. 
        /// </summary>
        /// <returns></returns>
        public bool ResumeThread()
        {
            bool bRet = false;
            try
            {
                int oldState = Kernel32.ResumeThread(hThread);
                bRet = (oldState > -1);
            }
            catch { }
            return bRet;
        }


        /// <summary>
        /// Query whether or not the current executing thread or process
        /// is still active. If it fails to query the thread, it then queries
        /// the process.
        /// </summary>
        /// <returns>TRUE if the module is still running, FALSE otherwise.</returns>
        public bool StillActive()
        {
            bool bRet = false;
            //int exitCode = 0;
            int dwRet;
            try
            {
                dwRet = Kernel32.GetExitCodeThread(hThread, out ExitCode);
                bRet = (ExitCode == 259); // 259 is STILL_ACTIVE
            }
            catch
            {
                try
                {
                    dwRet = Kernel32.GetExitCodeProcess(hProcess, out ExitCode);
                    bRet = (ExitCode == 259);
                }
                catch { }
            }
            return bRet;
        }

        /// <summary>
        /// Close all open handles the class manipulates.
        /// </summary>
        public void CloseHandles()
        {
            try
            {
                if (hThread != IntPtr.Zero)
                    Kernel32.CloseHandle(hThread);
            }
            catch { }
            try
            {
                if (hProcess != IntPtr.Zero)
                    Kernel32.CloseHandle(hProcess);
            }
            catch { }
        }

        /// <summary>
        /// Wrapper for creating a new remote thread in the target process.
        /// Specifically useful for when you need to spawn a suspended process
        /// and inject a running remote thread that you need output from.
        /// </summary>
        /// <param name="pic">Position-independent code that can be executable when jumped to.</param>
        /// <param name="arguments">Arguments to pass to this code, if any.</param>
        /// <returns></returns>
        //public bool CreateNewRemoteThread(byte[] pic, string arguments = "")
        //{
        //    bool bRet = false;
        //    CreateRemoteThreadInjection crt;
        //    try
        //    {
        //        crt = new CreateRemoteThreadInjection(pic, hProcess, arguments);
        //        Kernel32.CloseHandle(hThread);
        //        hThread = crt.RemoteThread;
        //        bRet = true;
        //    }
        //    catch (Exception ex)
        //    {

        //    }
        //    return bRet;
        //}
    }

    public class ProcessWithAnonymousPipeIO : SacrificialProcess
    {
        private static int BLOCK_SIZE = 4096;
        public int PID;

        public int ExitCode = 0;

        AnonymousPipeClientStream PipeClient;
        AnonymousPipeServerStream PipeServer;

        /// <summary>
        /// Constructor that will spawn a new process using named pipes as its I/O stream.
        /// If it fails to spawn the designated process, an error will be thrown.
        /// </summary>
        /// <param name="lpApplicationName">Application to spawn.</param>
        /// <param name="lpCommandLine">Any command line arguments to pass to the application.</param>
        /// <param name="processCreationFlags">Process creation flags to spawn the process with. By default, this is SUSPENDED.</param>
        /// <param name="useLogon">If true, this will use the current network logon token the agent has.</param>
        /// <param name="useCredentials">If true, this will first create a new logon session for the current credential set in Token.Cred and use that session to spawn a process.</param>
        public ProcessWithAnonymousPipeIO(string lpApplicationName, string lpCommandLine = "", Advapi32.ProcessCreationFlags processCreationFlags = Advapi32.ProcessCreationFlags.CREATE_SUSPENDED, bool useLogon = false, bool useCredentials = false, bool useToken = false)
        {
            if (useLogon && useCredentials)
            {
                throw new Exception("Cannot create a new process using the current logon session and using a set of credentials simultaneously.");
            }
            PipeSecurity sec = new PipeSecurity();
            sec.SetAccessRule(new PipeAccessRule("Everyone", PipeAccessRights.FullControl, AccessControlType.Allow));


            PipeServer = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable, 1024, sec);
            PipeClient = new AnonymousPipeClientStream(PipeDirection.Out, PipeServer.GetClientHandleAsString());
            //PipeServer.ReadTimeout = 10000;
            if (!CreateProcess(lpApplicationName, lpCommandLine, processCreationFlags, useLogon, useCredentials, useToken))
            {
                CloseHandles();
                throw new Exception("Failed to start child process.");
            }
        }

        /// <summary>
        /// Spawn a new process that respects tokens and credentials under the criterion
        /// of the creation flags and command line arguments given. This process will
        /// write to a named pipe stream given by PipeClient and its results are retrievable
        /// by the GetOutput enumerator. Once the process has finished executing, the caller
        /// should call CloseHandles() on this object.
        /// </summary>
        /// <param name="lpApplicationName">Application to spawn.</param>
        /// <param name="lpCommandLine">Any command line arguments to pass to the application.</param>
        /// <param name="processCreationFlags">Process creation flags to spawn the process with. By default, this is SUSPENDED.</param>
        /// <param name="useLogon">If true, this will use the current network logon token the agent has.</param>
        /// <param name="useCredentials">If true, this will first create a new logon session for the current credential set in Token.Cred and use that session to spawn a process.</param>
        private bool CreateProcess(string lpApplicationName, string lpCommandLine = "", Advapi32.ProcessCreationFlags processCreationFlags = Advapi32.ProcessCreationFlags.CREATE_SUSPENDED, bool useLogon = false, bool useCredentials = false, bool useToken = false)
        {
            Advapi32.PROCESS_INFORMATION piProcInfo = new Advapi32.PROCESS_INFORMATION();
            Advapi32.STARTUPINFO siStartInfo = new Advapi32.STARTUPINFO();
            Advapi32.SECURITY_ATTRIBUTES nullSecAttrs = new Advapi32.SECURITY_ATTRIBUTES();
            bool bSuccess;

            unsafe
            {
                siStartInfo.hStdError = PipeClient.SafePipeHandle.DangerousGetHandle();
                siStartInfo.hStdOutput = PipeClient.SafePipeHandle.DangerousGetHandle();
                siStartInfo.dwFlags = (int)Advapi32.STARTF.STARTF_USESTDHANDLES | (int)Advapi32.STARTF.STARTF_USESHOWWINDOW;
                siStartInfo.wShowWindow = 0;

                if (lpCommandLine != "")
                {
                    lpCommandLine = String.Format("{0} {1}", lpApplicationName, lpCommandLine);
                    //bSuccess = Kernel32.CreateProcessA(
                    //    "",
                    //    lpCommandLine,
                    //    nullSecAttrs,
                    //    nullSecAttrs,
                    //    true,
                    //    processCreationFlags,
                    //    IntPtr.Zero,
                    //    null,
                    //    siStartInfo,
                    //    out piProcInfo);
                }
                else
                {
                    lpCommandLine = lpApplicationName;
                }
                //else
                //    bSuccess = Kernel32.CreateProcessA(
                //        lpApplicationName,
                //        "",
                //        nullSecAttrs,
                //        nullSecAttrs,
                //        true,
                //        processCreationFlags,
                //        IntPtr.Zero,
                //        null,
                //        siStartInfo,
                //        out piProcInfo);

                
                bSuccess = Kernel32.CreateProcessA(
                    null,
                    lpCommandLine,
                    nullSecAttrs,
                    nullSecAttrs,
                    true,
                    processCreationFlags,
                    IntPtr.Zero,
                    null,
                    siStartInfo,
                    out piProcInfo);
                if (!bSuccess)
                {
                    return false;
                }
                //hProcess = piProcInfo.hProcess;
                hProcess = piProcInfo.hProcess;
                hThread = piProcInfo.hThread;
                PID = piProcInfo.dwProcessId;
                return true;
            }
        }

        /// <summary>
        /// Close all open handles the class manipulates.
        /// </summary>
        public void CloseHandles()
        {
            base.CloseHandles();
            try
            {
                if (PipeServer != null)
                    PipeServer.Close();
            }
            catch { }
            try
            {
                if (PipeClient != null)
                    PipeClient.Close();
            }
            catch { }
        }

        /// <summary>
        /// Read output from the process' named pipe I/O stream.
        /// </summary>
        /// <returns>String enumerator.</returns>
        public IEnumerable<string> GetOutput()
        {
            using (StreamReader reader = new StreamReader(PipeServer))
            {
                while (true)
                {
                    string output = "";
                    bool needBreak = false;
                    Action action;
                    if (!StillActive())
                    {
                        Debug.WriteLine("Process isn't active - reading until end.");
                        action = () =>
                        {
                            needBreak = true;
                            try
                            {
                                List<string> allOutput = new List<string>();
                                if (reader != null)
                                {
                                    while (reader.Peek() > -1)
                                    {
                                        allOutput.Add(reader.ReadLine());
                                    }
                                }
                                //allOutput.Add(reader.ReadLine());
                                output = String.Join("\n", allOutput.ToArray()).Trim();
                            }
                            catch (Exception ex)
                            {
                                // Fail silently if reader no longer exists
                                // May happen if long running job times out?
                                output = String.Format("[-] Error reading to end of stream: {0}", ex.Message);
                            }
                        };
                    }
                    else
                    {
                        action = () =>
                        {
                            try
                            {
                                //Char[] buffer = new Char[BLOCK_SIZE];
                                if (reader != null)
                                {
                                    if (reader.Peek() > -1)
                                    {
                                        output = reader.ReadLine();
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                // Fail silently if reader no longer exists
                                // May happen if long running job times out?
                                output = String.Format("[-] Error reading line from pipe stream: {0}", ex.Message);
                                needBreak = true;
                            }
                        };
                    }
                    IAsyncResult result = action.BeginInvoke(null, null);
                    if (result.AsyncWaitHandle.WaitOne(10000) && output != "" && output != null)
                    {
                        yield return output;
                    }
                    if (needBreak)
                        break;
                }
            }
        }

    }
}
