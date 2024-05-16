using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
//using System.Numerics;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            int result = (M*M) % (p*q);
            for(int i = 0; i < e -2 ; i++)
            {
                result *= M;
                result%= (p*q);
            }
            return result;
            //throw new NotImplementedException();
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int euler = (p - 1) * (q - 1);
            
            int d ;
            int A1 = 1, A2 = 0, A3 = euler;
            int B1 = 0, B2 = 1, B3 = e;
            while (true)
            {
                if (B3 == 1)
                {
                    d = (B2 % euler + euler) % euler;
                    break;
                }
                int Q = A3 / B3;
                int T1 = A1 - Q * B1;
                int T2 = A2 - Q * B2;
                int T3 = A3 - Q * B3;

                A1 = B1;
                A2 = B2;
                A3 = B3;

                B1 = T1;
                B2 = T2;
                B3 = T3;
            }
            int result = (C * C) % (p*q);
            for (int i = 0; i < d - 2; i++)
            {
                result *= C;
                result %= (p * q);
            }
            return result;
            throw new NotImplementedException();
        }

    }
}
