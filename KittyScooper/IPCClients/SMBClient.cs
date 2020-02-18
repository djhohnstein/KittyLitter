using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO.Pipes;
using System.Threading;
using System.Runtime.Serialization.Formatters.Binary;

namespace KittyScooper.IPCClients
{
    class SMBClient : IPCClient
    {
        string PipeName;
        BinaryFormatter bf;

        public SMBClient(string pipeName = "mswin32_application")
        {
            PipeName = pipeName;
            bf = new BinaryFormatter();
            bf.Binder = new IPCMessages.IPCMessage.IPCMessageBinder();
        }

        private static string FormatMessage(string host, string message)
        {
            string[] msgParts = message.Split('\n');
            string broadcastMessage = "";
            for (int i = 0; i < msgParts.Length; i++)
            {
                if (msgParts[i].Trim() != "")
                    broadcastMessage += String.Format("(SMB){0}{1}:\t{2}\n", Helpers.GetSpaces(30, host.Length + 5), host, msgParts[i]);
            }
            return broadcastMessage;
        }

        public override void ReadMessages(string host)
        {
            while (true)
            {
                NamedPipeClientStream clientStream = null;
                IPCMessages.IPCMessage msg;
                try
                {
                    clientStream = new NamedPipeClientStream(
                        host,
                        PipeName,
                        PipeDirection.InOut,
                        PipeOptions.Asynchronous);

                    clientStream.Connect(3000);
                    msg = (IPCMessages.IPCMessage)bf.Deserialize(clientStream);
                    string broadcastMessage = FormatMessage(host, msg.Message);
                    mtx.WaitOne();
                    Console.Write(broadcastMessage);
                    mtx.ReleaseMutex();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[-] Error in SMB Client when communicating with {host}: {ex.Message}");
                }
                finally
                {
                    if (clientStream != null)
                        clientStream.Close();
                }
                Thread.Sleep(30000);
            }
        }
    }
}
