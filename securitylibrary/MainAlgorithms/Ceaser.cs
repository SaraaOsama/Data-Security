using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            plainText = plainText.ToLower();
            Dictionary<char, int> d = new Dictionary<char, int>();
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            for (int i = 0; i < 26; i++)
                d[alphabet[i]] = i;
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < plainText.Length; i++)
                sb.Append(alphabet[((d[plainText[i]] + key) +26 ) % 26]);
            return sb.ToString();
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, int key)
        { 
            return Encrypt(cipherText,-key);
            //throw new NotImplementedException();
        }

        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            return (cipherText[0] - plainText[0] + 26) % 26;
            //throw new NotImplementedException();
        }
    }
}
