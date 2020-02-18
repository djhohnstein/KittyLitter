using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.Serialization;

namespace IPCMessages
{
    [Serializable]
    class IPCMessage
    {
        public string Message;

        public class IPCMessageBinder : SerializationBinder
        {
            public override Type BindToType(string assemblyName, string typeName)
            {
                if (typeName == "IPCMessages.IPCMessage")
                {
                    return typeof(IPCMessage);
                }
                else
                {
                    return typeof(Nullable);
                }
            }
        }
    }
}
