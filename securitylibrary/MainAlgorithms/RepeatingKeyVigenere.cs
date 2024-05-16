using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            plainText= plainText.ToLower();
            cipherText = cipherText.ToLower();
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            char[,] matrix = new char[26, 26];
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    matrix[i, j] = alphabet[(i + j) % 26];
                }
            }
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < plainText.Length; i++) {
                for(int j=0; j< alphabet.Length; j++) { 
                    if (Decrypt(cipherText[i].ToString(), alphabet[j].ToString()) == plainText[i].ToString()) {
                        result.Append(alphabet[j]);
                        break;
                    }
                }
            }
            char first = result[0];
            char second = result[1];
            StringBuilder result2 = new StringBuilder();
            for (int i = 0; i < result.Length; i++) {
                if ((first != result[i + 1]) || (second != result[i + 2]))
                {
                    result2.Append(result[i]);
                }
                else {
                    result2.Append(result[i]);
                    break;
                }
            }
            return result2.ToString();
            //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            StringBuilder key_stream = new StringBuilder();
            key_stream.Append(key);
            if (key.Length < cipherText.Length)
            {
                int dif = cipherText.Length - key.Length;

                for (int i = 0; i < dif; i++)
                {
                    key_stream.Append(key[i%key.Length]);
                }
            }

            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            char[,] matrix = new char[26, 26];
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    matrix[i, j] = alphabet[(i + j) % 26];
                }
            }
            StringBuilder plain_text = new StringBuilder();
            int key_length = key_stream.Length;
            for (int i = 0; i < key_length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (matrix[alphabet.IndexOf(key_stream[i]), j] == cipherText[i])
                    {
                        plain_text.Append(alphabet[j]);
                        break;
                    }
                }
            }
            return plain_text.ToString();
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            StringBuilder key_stream = new StringBuilder();
            key_stream.Append(key);
            if (key.Length < plainText.Length)
            {
                int dif = plainText.Length - key.Length;

                for (int i = 0; i < dif; i++)
                {
                    key_stream.Append(key_stream[i% key_stream.Length]);
                }
            }
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            char[,] matrix = new char[26, 26];
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    matrix[i, j] = alphabet[(i + j) % 26];
                }
            }
            StringBuilder encrypted = new StringBuilder();
            for (int i = 0; i < plainText.Length; i++)
            {
                encrypted.Append(matrix[alphabet.IndexOf(plainText[i]), alphabet.IndexOf(key_stream[i])]);
            }
            return encrypted.ToString();
            //throw new NotImplementedException();
        }
    }
}