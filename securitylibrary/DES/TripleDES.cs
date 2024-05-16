using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        DES ob = new DES();
        public string Decrypt(string cipherText, List<string> key)
        {
            string en1 = ob.Decrypt(cipherText, key[0]);
            string en2 = ob.Encrypt(en1, key[1]);
            string en3 = ob.Decrypt(en2, key[0]);
            return en3;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            string en1 = ob.Encrypt(plainText, key[0]);
            string en2 = ob.Decrypt(en1, key[1]);
            string en3 = ob.Encrypt(en2, key[0]);
            return en3;
        }
        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
