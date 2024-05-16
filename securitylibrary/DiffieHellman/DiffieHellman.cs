using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        private int Power(int alpha, int x, int q)
        {
            if (x == 0)
                return 1;

            long result = 1;
            long basevalue = alpha % q;

            for (int i = 0; i < x; i++)
            {
                result = (result * basevalue) % q;
            }

            return (int)result;
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int result1 = Power(alpha, xa, q);
            int result2 = Power(alpha, xb, q);

            int final1 = Power(result2, xa, q);
            int final2 = Power(result1, xb, q);

            List<int> final = new List<int>();
            final.Add(final1);
            final.Add(final2);
            return final;
            throw new NotImplementedException();
        }
    }
}
