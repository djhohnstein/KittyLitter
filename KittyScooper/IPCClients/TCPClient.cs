using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace KittyScooper.IPCClients
{
    class TCPClient : IPCClient
    {
        int Port;

        public TCPClient(int port)
        {
            Port = port;
        }

        private static string FormatMessage(string host, string message)
        {
            string[] msgParts = message.Split('\n');
            string broadcastMessage = "";
            for (int i = 0; i < msgParts.Length; i++)
            {
                if (msgParts[i].Trim() != "")
                    broadcastMessage += String.Format("(TCP){0}{1}:\t{2}\n", Helpers.GetSpaces(30, host.Length + 5), host, msgParts[i]);
            }
            return broadcastMessage;
        }

        public override void ReadMessages(string host)
        {
            while (true)
            {
                try
                {
                    // Create a TcpClient.
                    // Note, for this client to work you need to have a TcpServer 
                    // connected to the same address as specified by the server, port
                    // combination.
                    TcpClient client = new TcpClient(host, Port);

                    // Get a client stream for reading and writing.
                    //  Stream stream = client.GetStream();

                    string str;
                    using (NetworkStream stream = client.GetStream())
                    {
                        byte[] data = new byte[1024];
                        using (MemoryStream ms = new MemoryStream())
                        {

                            int numBytesRead;
                            while ((numBytesRead = stream.Read(data, 0, data.Length)) > 0)
                            {
                                ms.Write(data, 0, numBytesRead);


                            }
                            str = Encoding.ASCII.GetString(ms.ToArray(), 0, (int)ms.Length);
                        }
                    }
                    if (str != "")
                    {
                        mtx.WaitOne();
                        Console.Write(FormatMessage(host, str));
                        mtx.ReleaseMutex();
                    }


                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] TCPClient {0}, Exception: {1}", host, ex.Message);
                }
                System.Threading.Thread.Sleep(30000);
            }
        }
    }
}
