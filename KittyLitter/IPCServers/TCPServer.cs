using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace KittyLitter.IPCServers
{
    class TCPServer : IPCServer
    {
        Int32 Port;
        TcpListener Server = null;
        public TCPServer(Int32 port = 1337)
        {
            Port = port;
            IPAddress anyAddr = IPAddress.Any;
            try
            {
                Server = new TcpListener(anyAddr, Port);
                Server.Start();
            } catch
            {
                Server = null;
            }
        }

        public override void ServeServer()
        {
            // Enter the listening loop.
            while (true && Server != null)
            {
                TcpClient client = null;
                try
                {
                    // Perform a blocking call to accept requests.
                    // You could also user server.AcceptSocket() here.
                    client = Server.AcceptTcpClient();
                    
                    // Get a stream object for reading and writing
                    NetworkStream stream = client.GetStream();


                    byte[] msg = System.Text.Encoding.ASCII.GetBytes(Message + "\n");

                    // Send back a response.
                    stream.Write(msg, 0, msg.Length);
                    //Console.WriteLine("Sent: {0}", data);

                    // Shutdown and end connection
                    client.Close();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("TCPServer Excecption: {0}", ex.Message);
                } finally
                {
                    if (client != null && client.Connected)
                        client.Close();
                }
            }
        }
    }
}
