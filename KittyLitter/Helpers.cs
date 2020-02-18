using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace KittyLitter
{
    class Helpers
    {
        static byte[] XorByteArray(byte[] origBytes, char[] cryptor)
        {
            byte[] result = new byte[origBytes.Length];
            int j = 0;
            for (int i = 0; i < origBytes.Length; i++)
            {
                // If we're at the end of the encryption key, move
                // pointer back to beginning.
                if (j == cryptor.Length - 1)
                {
                    j = 0;
                }
                // Perform the XOR operation
                byte res = (byte)(origBytes[i] ^ Convert.ToByte(cryptor[j]));
                // Store the result
                result[i] = res;
                // Increment the pointer of the XOR key
                j += 1;
            }
            // Return results
            return result;
        }


        public static byte[] GetPIC()
        {
            char[] cryptor = "KittyLitter".ToCharArray();
            return XorByteArray(Properties.Resources.lsamanager, cryptor);
        }

    }
}
