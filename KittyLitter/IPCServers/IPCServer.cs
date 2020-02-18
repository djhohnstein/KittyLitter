using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace KittyLitter.IPCServers
{
    abstract class IPCServer
    {
        internal static string Message = "Not Set";
        internal static int SleepTime = 10 * 1000;

        public static void SetMessage(string msg)
        {
            Message = msg;
        }

        public abstract void ServeServer();
    }
}
