using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            Dictionary<char, char> keyMap = new Dictionary<char, char>();
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            for (int i = 0; i < plainText.Length; i++)
            {
                keyMap[plainText[i]] = cipherText[i];
            }

            for (int i = 0; i < alphabet.Length; i++){
                if (!keyMap.ContainsKey(alphabet[i])){
                    for (int j = 0; j < alphabet.Length; j++){
                        if (!keyMap.Values.Contains(alphabet[j])){
                            keyMap[alphabet[i]] = alphabet[j];
                            break;
                        }
                    }
                }
            }

            StringBuilder result = new StringBuilder();
            for (int i = 0; i < 26; i++){
                result.Append(keyMap[alphabet[i]]);
            }
            return result.ToString();

            //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string alpha = "abcdefghijklmnopqrstuvwxyz";
            Dictionary<char, char> d = new Dictionary<char, char>();
            for (int i = 0; i < 26; i++)
            {
                d[alpha[i]] = key[i];

            }
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (cipherText[i] == d[alpha[j]])
                    {
                        result.Append(alpha[j]);
                    }
                }
            }

            return result.ToString();
            throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            string alpha = "abcdefghijklmnopqrstuvwxyz";
            char[] alphabet = alpha.ToCharArray();
            char[] PT = plainText.ToCharArray();
            char[] KEY = key.ToCharArray();
            char[] cipher = new char[PT.Length];
            for (int i = 0; i < PT.Length; i++)
            {
                for (int j = 0; j < alphabet.Length; j++)
                {
                    if (PT[i] == alphabet[j])
                        cipher[i] = KEY[j];
                }
            }
            string CT = new string(cipher);
            return CT;
            throw new NotImplementedException();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        /// 


        public string AnalyseUsingCharFrequency(string cipher)
        {
            cipher = cipher.ToLower();
            string sequence = "etaoinsrhdlcumwfgypbvkjxqz";
            Dictionary<char, int> letterCounts = new Dictionary<char, int>();
            foreach (char letter in sequence)
                letterCounts[letter] = 0;
            foreach (char letter in cipher)
                letterCounts[letter]++;
            letterCounts = letterCounts.OrderByDescending(pair => pair.Value).ToDictionary(pair => pair.Key, pair => pair.Value);
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < cipher.Length; i++)
                for (int j = 0; j < letterCounts.Count; j++)
                    if (cipher[i] == letterCounts.ElementAt(j).Key) {
                        result.Append(sequence[j]);
                        break;
                    }
            return result.ToString();
            //throw new NotImplementedException();
        }
    }
}
