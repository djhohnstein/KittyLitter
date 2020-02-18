using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace KittyScooper
{
    class Helpers
    {
        public static string GetSpaces(int maxSpaces, int sideStringLength)
        {
            string spaces = "";
            if (sideStringLength > maxSpaces)
                return spaces;
            for(int i = 0; i < maxSpaces - sideStringLength; i++)
            {
                spaces += " ";
            }
            return spaces;
        }
    }
}
