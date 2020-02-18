using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace KittyScooper
{
    class Program
    {
        static void Main(string[] args)
        {
            string host = "localhost";
            if (args.Length >= 1)
                host = args[0];
            Console.WriteLine("Targeting {0}", host);
            IPCClients.SMBClient smb = new IPCClients.SMBClient();
            //smb.ReadMessages("localhost");
            IPCClients.MailSlotClient mail = new IPCClients.MailSlotClient("mswin32_application");
            //client.ReadMessages("");
            IPCClients.TCPClient tcp = new IPCClients.TCPClient(1337);
            //client.ReadMessages("localhost");
            IPCClients.IPCClient[] clients = new IPCClients.IPCClient[] { smb, mail, tcp };
            foreach(var c in clients)
            {
                Thread t = new Thread(() => c.ReadMessages("localhost"));
                t.Start();
            }
        }
    }
}
