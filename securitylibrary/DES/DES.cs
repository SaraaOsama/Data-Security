using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    public class DES : CryptographicTechnique
    {
        static string HexStringToBinary(string hexString)
        {
            string hexWithoutPrefix = hexString.Substring(2);
            ulong intValue = ulong.Parse(hexWithoutPrefix, System.Globalization.NumberStyles.HexNumber);
            string binaryString = Convert.ToString((long)intValue, 2).PadLeft(hexWithoutPrefix.Length * 4, '0');
            return binaryString;
        }
        static string getKey(string key)
        {
            int[,] numbers = new int[,]
            {
            {57, 49, 41, 33, 25, 17, 9},
            {1, 58, 50, 42, 34, 26, 18},
            {10, 2, 59, 51, 43, 35, 27},
            {19, 11, 3, 60, 52, 44, 36},
            {63, 55, 47, 39, 31, 23, 15},
            {7, 62, 54, 46, 38, 30, 22},
            {14, 6, 61, 53, 45, 37, 29},
            {21, 13, 5, 28, 20, 12, 4}
            };
            string ans = "";
            for (int i = 0; i < 8; i++)
                for (int j = 0; j < 7; j++)
                    ans += key[numbers[i, j] - 1];
            return ans;
        }
        static string shif(string s, int len)
        {
            List<char> list = s.ToList();
            while (len > 0)
            {
                len--;
                char c = list[0];
                list.RemoveAt(0);
                list.Add(c);
            }
            string resultString = new string(list.ToArray());
            return resultString;
        }
        static List<string> GroupBinary(string binary)
        {
            List<string> groupedBinary = new List<string>();
            for (int i = 0; i < binary.Length; i += 4)
                groupedBinary.Add(binary.Substring(i, 4));
            return groupedBinary;
        }
        static string ConvertBinaryToHex(List<string> groupedBinary)
        {
            string hexValue = "";
            foreach (string group in groupedBinary)
            {
                int decimalValue = Convert.ToInt32(group, 2);
                string hexGroup = Convert.ToString(decimalValue, 16).ToUpper();
                hexValue += hexGroup;
            }
            return hexValue;
        }
        static string xx(string a, string b)
        {
            string ans = "";
            for (int i = 0; i < 32; i++)
                ans += (a[i] == b[i]) ? '0' : '1';
            return ans;
        }
        static string mangler(string r, string key)
        {
            int[,] EBitSelectionTable = new int[8, 6] {
            { 32, 1, 2, 3, 4, 5 },
            { 4, 5, 6, 7, 8, 9 },
            { 8, 9, 10, 11, 12, 13 },
            { 12, 13, 14, 15, 16, 17 },
            { 16, 17, 18, 19, 20, 21 },
            { 20, 21, 22, 23, 24, 25 },
            { 24, 25, 26, 27, 28, 29 },
            { 28, 29, 30, 31, 32, 1 }
          };
            string afterExpantional = "";
            for (int i = 0; i < 8; i++)
                for (int j = 0; j < 6; j++)
                    afterExpantional += r[EBitSelectionTable[i, j] - 1];
            string ans = "";
            for (int i = 0; i < 48; i++)
                ans += (key[i] == afterExpantional[i]) ? '0' : '1';
            List<string> BIT6 = new List<string>();
            for (int i = 0; i < 48; i += 6)
                BIT6.Add(ans.Substring(i, 6));
            List<int[,]> listOfArrays = new List<int[,]>();
            int[,] s1Grid = new int[,]
             {
            {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
            {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
            {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
            {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
             };

            int[,] s2Grid = new int[,]
            {
            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
            {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
            {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
            {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
            };
            int[,] s3Grid = new int[,]
           {
            {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
            {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
            {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
            {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
           };
            int[,] s4Grid = new int[,]
            {
            {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
            {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
            {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
            {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
            };
            int[,] s5Grid = new int[,]
            {
            {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
            {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
            {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
            {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
            };
            int[,] s6Grid = new int[,]
           {
            {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
            {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
            {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
            {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
           };
            int[,] s7Grid = new int[,]
           {
            {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
            {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
            {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
            {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
           };
            int[,] s8Grid = new int[,]
           {
            {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
            {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
            {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
            {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
           };
            listOfArrays.Add(s1Grid);
            listOfArrays.Add(s2Grid);
            listOfArrays.Add(s3Grid);
            listOfArrays.Add(s4Grid);
            listOfArrays.Add(s5Grid);
            listOfArrays.Add(s6Grid);
            listOfArrays.Add(s7Grid);
            listOfArrays.Add(s8Grid);
            string fans = "";
            for (int i = 0; i < 8; i++)
            {
                int[,] sgrid = listOfArrays[i];
                string bt = BIT6[i];
                string f = "";
                f += bt[0];
                f += bt[5];
                string s = "";
                for (int j = 1; j <= 4; j++)
                    s += bt[j];
                string ians = "";
                for (int j = 0; j < 4; j++)
                {
                    string c = stre(Convert.ToString(j, 2), 2);
                    if (!c.Equals(f, StringComparison.OrdinalIgnoreCase))
                        continue;
                    for (int k = 0; k < 16; k++)
                    {
                        string cc = stre(Convert.ToString(k, 2), 4);
                        if (!cc.Equals(s, StringComparison.OrdinalIgnoreCase))
                            continue;
                        ians = stre(Convert.ToString(sgrid[j, k], 2), 4);
                    }
                }
                fans += ians;
            }
            string ffans = "";
            int[,] pp = new int[,]
            {
            {16, 7, 20, 21},
            {29, 12, 28, 17},
            {1, 15, 23, 26},
            {5, 18, 31, 10},
            {2, 8, 24, 14},
            {32, 27, 3, 9},
            {19, 13, 30, 6},
            {22, 11, 4, 25}
            };
            for (int i = 0; i < 8; i++)
                for (int j = 0; j < 4; j++)
                    ffans += fans[pp[i, j] - 1];
            return ffans;
        }
        static string GetInverseString(string input)
        {
            char[] charArray = input.ToCharArray();
            int length = charArray.Length;
            for (int i = 0; i < length / 2; i++)
            {
                char temp = charArray[i];
                charArray[i] = charArray[length - i - 1];
                charArray[length - i - 1] = temp;
            }
            string reversedString = new string(charArray);
            return reversedString;
        }
        static string stre(string c, int len)
        {
            c = GetInverseString(c);
            while (c.Length < len)
                c += '0';
            c = GetInverseString(c);
            return c;
        }
        static List<String> getAllKeys(string key)
        {
            string keyInBinary = HexStringToBinary(key);
            string keyAfterPermuation = getKey(keyInBinary);
            string c0 = "";
            string d0 = "";
            for (int i = 0; i < 56; i++)
            {
                if (i < 28)
                    c0 += keyAfterPermuation[i];
                else
                    d0 += keyAfterPermuation[i];
            }
            int[] shiftNum = new int[]
           {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
            List<string> c = new List<string>();
            List<string> d = new List<string>();
            c.Add(c0);
            d.Add(d0);
            for (int i = 0; i <= 15; i++)
            {
                c.Add(shif(c[i], shiftNum[i]));
                d.Add(shif(d[i], shiftNum[i]));
            }
            List<string> keys = new List<string>();
            int[,] pc_2 = new int[,]
            {
            {14, 17, 11, 24, 1, 5},
            {3, 28, 15, 6, 21, 10},
            {23, 19, 12, 4, 26, 8},
            {16, 7, 27, 20, 13, 2},
            {41, 52, 31, 37, 47, 55},
            {30, 40, 51, 45, 33, 48},
            {44, 49, 39, 56, 34, 53},
            {46, 42, 50, 36, 29, 32}
            };
            for (int i = 1; i <= 16; i++)
            {
                string ans = c[i] + d[i];
                string fans = "";
                for (int o = 0; o < 8; o++)
                    for (int k = 0; k < 6; k++)
                        fans += ans[pc_2[o, k] - 1];
                keys.Add(fans);
            }
            return keys;
        }
        static string IniPermuation(string plaintext)
        {
            string binaryString = HexStringToBinary(plaintext);
            int[,] initialPermutationTable = new int[8, 8]
            {
            { 58, 50, 42, 34, 26, 18, 10, 2 },
            { 60, 52, 44, 36, 28, 20, 12, 4 },
            { 62, 54, 46, 38, 30, 22, 14, 6 },
            { 64, 56, 48, 40, 32, 24, 16, 8 },
            { 57, 49, 41, 33, 25, 17, 9, 1 },
            { 59, 51, 43, 35, 27, 19, 11, 3 },
            { 61, 53, 45, 37, 29, 21, 13, 5 },
            { 63, 55, 47, 39, 31, 23, 15, 7 }
            };
            string afterPermutation = "";
            for (int i = 0; i < 8; i++)
                for (int j = 0; j < 8; j++)
                    afterPermutation += binaryString[initialPermutationTable[i, j] - 1];
            return afterPermutation;
        }
        static string finalPermutation(string s)
        {
            int[,] f_permutation = new int[,]
            {
            {40, 8, 48, 16, 56, 24, 64, 32},
            {39, 7, 47, 15, 55, 23, 63, 31},
            {38, 6, 46, 14, 54, 22, 62, 30},
            {37, 5, 45, 13, 53, 21, 61, 29},
            {36, 4, 44, 12, 52, 20, 60, 28},
            {35, 3, 43, 11, 51, 19, 59, 27},
            {34, 2, 42, 10, 50, 18, 58, 26},
            {33, 1, 41, 9, 49, 17, 57, 25}
            };
            string final = "";
            for (int i = 0; i < 8; i++)
                for (int j = 0; j < 8; j++)
                    final += s[f_permutation[i, j] - 1];
            return final;
        }
        static string finalFormat(string s)
        {
            List<string> gh = new List<string>();
            List<string> groupedBinary = GroupBinary(s);
            string hexadecimalNumber = ConvertBinaryToHex(groupedBinary);
            hexadecimalNumber = GetInverseString(hexadecimalNumber);
            hexadecimalNumber += "x0";
            hexadecimalNumber = GetInverseString(hexadecimalNumber);
            return hexadecimalNumber;
        }
        public override string Decrypt(string cipherText, string key)
        {
            string afterPermutation = IniPermuation(cipherText);
            List<string> keys = getAllKeys(key);
            string l0 = "", r0 = "";
            for (int i = 0; i < 64; i++)
                if (i < 32)
                    r0 += afterPermutation[i];
                else
                    l0 += afterPermutation[i];

            List<string> l = new List<string>();
            List<string> r = new List<string>();
            keys.Reverse();
            l.Add(l0);
            r.Add(r0);
            int cnt = 0;
            while (cnt < 16)
            {
                r.Add(l[cnt]);
                l.Add(xx(mangler(l[cnt], keys[cnt]), r[cnt]));
                cnt++;
            }
            string re = l[l.Count - 1] + r[r.Count - 1];
            string final = finalPermutation(re);
            string hexaFormat = finalFormat(final);
            return hexaFormat;
        }
        public override string Encrypt(string plainText, string key)
        {
            string binaryString = HexStringToBinary(plainText);
            List<string> keys = getAllKeys(key);
            string afterPermuation = IniPermuation(plainText);
            string l0 = "", r0 = "";
            for (int i = 0; i < 64; i++)
                if (i < 32)
                    l0 += afterPermuation[i];
                else
                    r0 += afterPermuation[i];
            List<string> l = new List<string>();
            List<string> r = new List<string>();
            l.Add(l0);
            r.Add(r0);
            int cnt = 0;
            while (cnt < 16)
            {
                l.Add(r[cnt]);
                r.Add(xx(mangler(r[cnt], keys[cnt]), l[cnt]));
                cnt++;
            }
            string re = r[r.Count - 1] + l[l.Count - 1];
            string final = finalPermutation(re);
            string hexaFormat = finalFormat(final);
            return hexaFormat;
        }
    }
}
