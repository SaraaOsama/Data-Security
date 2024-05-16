using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            char[,] matrix = new char[5, 5];
            key = key + "ABCDEFGHIKLMNOPQRSTUVWXYZ";
            key = key.ToLower();
            key = new string(key.Distinct().ToArray());
            key = key.Replace(" ", "");
            int indx = 0;
            bool ex = false;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (ex)
                    {
                        if (key[indx] == 'i' || key[indx] == 'j')
                        {
                            indx++;
                            matrix[i, j] = key[indx++];
                            continue;
                        }
                    }
                    if (key[indx] == 'i' || key[indx] == 'j')
                        ex = true;
                    matrix[i, j] = key[indx++];
                }
            }
            Dictionary<char, Tuple<int, int>> pos = new Dictionary<char, Tuple<int, int>>();
            //pos.Add('i', Tuple.Create(0,0));
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    pos.Add(matrix[i, j], Tuple.Create(i, j));
                    if (matrix[i, j] == 'j' || matrix[i, j] == 'i')
                    {
                        if (!pos.ContainsKey('i'))
                            pos.Add('i', Tuple.Create(i, j));
                        if (!pos.ContainsKey('j'))
                            pos.Add('j', Tuple.Create(i, j));
                    }
                }
            }
            string s = cipherText;
            s = s.ToLower();
            s = s.Replace(" ", "");
            // Console.WriteLine(s);
            List<Tuple<char, char>> myList = new List<Tuple<char, char>>();
            int cx = 0;
            for (int i = 0; i < s.Length - 1; i++)
            {
                if (s[i] == s[i + 1])
                {
                    myList.Add(new Tuple<char, char>(s[i], 'x'));
                    cx++;
                }
                else
                {
                    myList.Add(new Tuple<char, char>(s[i], s[i + 1]));
                    i++;
                }
            }
            if (s.Length >= 2)
            {
                if (s[s.Length - 1] == s[s.Length - 2] || (((int)s.Length - cx) % 2) == 1)
                {
                    myList.Add(new Tuple<char, char>(s[s.Length - 1], 'x'));
                }
            }
            else if (s.Length == 1)
            {
                myList.Add(new Tuple<char, char>(s[0], 'x'));
            }
            string ans = "";
            foreach (var e in myList)
            {
                // Console.WriteLine(e);
                var pos1 = pos[e.Item1];
                var pos2 = pos[e.Item2];
                if (pos1.Item1 == pos2.Item1)
                {
                    char c1 = matrix[pos1.Item1, (pos1.Item2 - 1 + 5) % 5];
                    char c2 = matrix[pos2.Item1, (pos2.Item2 - 1 + 5) % 5];
                    ans += c1;
                    ans += c2;
                }
                else if (pos1.Item2 == pos2.Item2)
                {
                    char c1 = matrix[(pos1.Item1 - 1 + 5) % 5, pos1.Item2];
                    char c2 = matrix[(pos2.Item1 - 1 + 5) % 5, pos2.Item2];
                    ans += c1;
                    ans += c2;
                }
                else
                {
                    char c1 = matrix[pos1.Item1, pos2.Item2];
                    char c2 = matrix[pos2.Item1, pos1.Item2];
                    ans += c1;
                    ans += c2;
                }
            }
            ans = ans.Replace("x", "");
            return ans;
        }

        public string Encrypt(string plainText, string key)
        {
            char[,] matrix = new char[5, 5];
            key = key + "ABCDEFGHIKLMNOPQRSTUVWXYZ";
            key = key.ToLower();
            key = new string(key.Distinct().ToArray());
            key = key.Replace(" ", "");
            int indx = 0;
            bool ex = false;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (ex)
                    {
                        if (key[indx] == 'i' || key[indx] == 'j')
                        {
                            indx++;
                            matrix[i, j] = key[indx++];
                            continue;
                        }
                    }
                    if (key[indx] == 'i' || key[indx] == 'j')
                        ex = true;
                    matrix[i, j] = key[indx++];
                }
            }
            Dictionary<char, Tuple<int, int>> pos = new Dictionary<char, Tuple<int, int>>();
            //pos.Add('i', Tuple.Create(0,0));
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    pos.Add(matrix[i, j], Tuple.Create(i, j));
                    if (matrix[i, j] == 'j' || matrix[i, j] == 'i')
                    {
                        if (!pos.ContainsKey('i'))
                            pos.Add('i', Tuple.Create(i, j));
                        if (!pos.ContainsKey('j'))
                            pos.Add('j', Tuple.Create(i, j));
                    }
                }
            }
            string s = plainText;
            s = s.ToLower();
            s = s.Replace(" ", "");
            // Console.WriteLine(s);
            List<Tuple<char, char>> myList = new List<Tuple<char, char>>();
            int cx = 0;
            for (int i = 0; i < s.Length - 1; i++)
            {
                if (s[i] == s[i + 1])
                {
                    myList.Add(new Tuple<char, char>(s[i], 'x'));
                    cx++;
                }
                else
                {
                    myList.Add(new Tuple<char, char>(s[i], s[i + 1]));
                    i++;
                }
            }
            if (s.Length >= 2)
            {
                if (s[s.Length - 1] == s[s.Length - 2] || (((int)s.Length - cx) % 2) == 1)
                {
                    myList.Add(new Tuple<char, char>(s[s.Length - 1], 'x'));
                }
            }
            else if (s.Length == 1)
            {
                myList.Add(new Tuple<char, char>(s[0], 'x'));
            }
            string ans = "";
            foreach (var e in myList)
            {
                // Console.WriteLine(e);
                var pos1 = pos[e.Item1];
                var pos2 = pos[e.Item2];
                if (pos1.Item1 == pos2.Item1)
                {
                    char c1 = matrix[pos1.Item1, (pos1.Item2 + 1) % 5];
                    char c2 = matrix[pos2.Item1, (pos2.Item2 + 1) % 5];
                    ans += c1;
                    ans += c2;
                }
                else if (pos1.Item2 == pos2.Item2)
                {
                    char c1 = matrix[(pos1.Item1 + 1) % 5, pos1.Item2];
                    char c2 = matrix[(pos2.Item1 + 1) % 5, pos2.Item2];
                    ans += c1;
                    ans += c2;
                }
                else
                {
                    char c1 = matrix[pos1.Item1, pos2.Item2];
                    char c2 = matrix[pos2.Item1, pos1.Item2];
                    ans += c1;
                    ans += c2;
                }
            }
            return ans;
        }
    }
}
