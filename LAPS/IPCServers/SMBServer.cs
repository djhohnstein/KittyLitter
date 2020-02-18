using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Runtime.Serialization.Formatters.Binary;

namespace KittyLitter.IPCServers
{
    class SMBServer : IPCServer
    {

        string PipeName;
        BinaryFormatter bf;


        public SMBServer(string pipeName = "mswin32_application")
        {
            PipeName = pipeName;
            bf = new BinaryFormatter();
            bf.Binder = new IPCMessages.IPCMessage.IPCMessageBinder();
        }

        public override void ServeServer()
        {
            while (true)
            {
                NamedPipeServerStream server = null;
                try
                {
                    server = CreateNamedPipeServer();
                    server.WaitForConnection();
                    IPCMessages.IPCMessage msg = new IPCMessages.IPCMessage()
                    {
                        Message = Message
                    };
                    bf.Serialize(server, msg);
                } catch (Exception ex)
                {
                    Console.WriteLine($"[-] Exception in SMBServer: {ex.Message}");
                } finally
                {
                    if (server != null && server.IsConnected)
                    {
                        try
                        {
                            server.WaitForPipeDrain();
                            server.Close();
                        }
                        catch { }
                        finally
                        {

                        }
                    }
                }
            }
        }

        private NamedPipeServerStream CreateNamedPipeServer()
        {
            PipeSecurity pipeSecurityDescriptor = new PipeSecurity();
            PipeAccessRule everyoneAllowedRule = new PipeAccessRule("Everyone", PipeAccessRights.ReadWrite, AccessControlType.Allow);
            PipeAccessRule networkAllowRule = new PipeAccessRule("Network", PipeAccessRights.ReadWrite, AccessControlType.Allow);       // This should only be used locally, so lets limit the scope
            pipeSecurityDescriptor.AddAccessRule(everyoneAllowedRule);
            pipeSecurityDescriptor.AddAccessRule(networkAllowRule);

            // Gotta be careful with the buffer sizes. There's a max limit on how much data you can write to a pipe in one sweep. IIRC it's ~55,000, but I dunno for sure.
            NamedPipeServerStream pipeServer = new NamedPipeServerStream(PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 32768, 32768, pipeSecurityDescriptor);

            return pipeServer;
        }
    }
}
