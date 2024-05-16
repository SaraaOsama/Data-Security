using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        bool encisHexa = false;
        public override string Decrypt(string cipherText, string key)
        {
            return Encrypt(cipherText, key);
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            byte[] plaintextBytes;
            if (plainText.StartsWith("0x"))
            {
                encisHexa = true;
                plainText = HexToAscii(plainText);
                plaintextBytes = Encoding.Default.GetBytes(plainText);
            }
            else
            {
                plaintextBytes = Encoding.Default.GetBytes(plainText);
            }
            byte[] keyBytes;
            if (key.Contains("0x"))
            {
                key = HexToAscii(key);
                keyBytes = Encoding.Default.GetBytes(key);
            }
            else
            {
                keyBytes = Encoding.Default.GetBytes(key);
            }
            byte[] ciphertextBytes = rc(plaintextBytes, keyBytes);
            string ciphertext ="";
            for (int i = 0; i < ciphertextBytes.Length; i++)
            {
                ciphertext += (char)(ciphertextBytes[i]);
            }
            if (encisHexa)
            {
                string temp = "0x";
                foreach (char c in ciphertext)
                {
                    int asciiValue = (int)c;
                    temp += asciiValue.ToString("X2");
                }
                ciphertext = temp;
            }
            return ciphertext;
            //throw new NotImplementedException();
        }

        public string HexToAscii(string hexString)
        {
            hexString = hexString.Substring(2);
            byte[] bytes = new byte[hexString.Length / 2];
            for (int i = 0; i < hexString.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            }
            string asciiString = Encoding.Default.GetString(bytes);
            return asciiString;
        }
        private byte[] rc(byte[] input, byte[] key)
        {
            byte[] S = new byte[256];
            for (int k = 0; k < 256; k++)
            {
                S[k] = (byte)k;
            }
            int j = 0;
            for (int  k= 0; k < 256; k++)
            {
                j = (j + S[k] + key[k % key.Length]) % 256;
                byte temp = S[k];
                S[k] = S[j];
                S[j] = temp;
            }
            byte[] output = new byte[input.Length];
            int i = 0;
            j = 0;
            for (int index = 0; index < input.Length; index++)
            {
                i = (i + 1) % 256;
                j = (j + S[i]) % 256;

                byte temp = S[i];
                S[i] = S[j];
                S[j] = temp;

                int t = (S[i] + S[j]) % 256;
                byte k = S[t];

                output[index] = (byte)(input[index] ^ k);
            }
            return output;
        }
    }
}