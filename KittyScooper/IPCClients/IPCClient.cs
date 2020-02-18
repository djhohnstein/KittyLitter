using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace KittyScooper.IPCClients
{
    abstract class IPCClient
    {
        internal static Mutex mtx = new Mutex();
        public abstract void ReadMessages(string host);
    }
}
