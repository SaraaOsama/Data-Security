using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        private static List<List<int>> GetPermutations(int[] nums, int n)
        {
            var result = new List<List<int>>();
            Permute(nums, 0, n - 1, result);
            return result;
        }

        private static void Permute(int[] nums, int start, int end, List<List<int>> result)
        {
            if (start == end)
            {
                result.Add(new List<int>(nums));
            }
            else
            {
                for (int i = start; i <= end; i++)
                {
                    Swap(ref nums[start], ref nums[i]);
                    Permute(nums, start + 1, end, result);
                    Swap(ref nums[start], ref nums[i]); // backtrack
                }
            }
        }

        private static void Swap(ref int a, ref int b)
        {
            int temp = a;
            a = b;
            b = temp;
        }


        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            for (int i = 2; i <= 9; i++)
            {
                List<int> list = new List<int>();
                for (int j = 1; j <= i; j++)
                {
                    list.Add(j);

                }
                int[] myarray = list.ToArray();
                var permutations = GetPermutations(myarray, myarray.Length);
                foreach (var perm in permutations)
                {
                    if ((Decrypt(cipherText, perm) == plainText) || (Encrypt(plainText, perm) == cipherText))
                        return perm;
                }
            }
            throw new NotImplementedException();
        }

        public string Decrypt(string encryptedText, List<int> key)
        {
            encryptedText = encryptedText.ToLower();
            int num_of_columns = key.Max();
            int num_of_rows = encryptedText.Length % num_of_columns == 0 ? encryptedText.Length / num_of_columns : encryptedText.Length / num_of_columns + 1;

            char[,] decrypted = new char[num_of_rows, num_of_columns];
            for (int i = 0; i < num_of_rows; i++)
                for (int j = 0; j < num_of_columns; j++)
                    decrypted[i, j] = 'x';
            Dictionary<int, int> keyMap = new Dictionary<int, int>();



            //for (int i = 0; i < key.Count; i++)
            //{
            //    keyMap[key.Min()] = key.IndexOf(key.Min());
            //    key[key.IndexOf(key.Min())] = 999999999;
            //}


            for (int i = 0; i < key.Count; i++)
            {
                keyMap[key[i]] = i;
            }


            int counter = 1;
            int current_row = 0, current_column = keyMap[counter];
            int plainText_length = encryptedText.Length;
            for (int i = 0; i < plainText_length; i++)
            {
                decrypted[current_row, current_column] = encryptedText[i];
                current_row++;
                if (current_row == num_of_rows)
                {
                    current_row = 0;
                    counter++;
                    if (counter != key.Count+1)
                        current_column = keyMap[counter];
                }
            }
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < num_of_rows; i++)
            {
                for (int j = 0; j < num_of_columns; j++)
                {
                    result.Append(decrypted[i, j]);
                }
            }
            return result.ToString();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            //plainText = plainText.ToLower();
            StringBuilder temp = new StringBuilder();
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] == ' ')
                    continue;
                else
                    temp.Append(plainText[i]);
            }
            string plain_text_without_spaces = temp.ToString();
            int num_of_columns = key.Max();
            int num_of_rows = plain_text_without_spaces.Length % num_of_columns == 0 ? plain_text_without_spaces.Length / num_of_columns : plain_text_without_spaces.Length / num_of_columns + 1;
            char[,] encrypted = new char[num_of_rows, num_of_columns];
            for (int i = 0; i < num_of_rows; i++)
                for (int j = 0; j < num_of_columns; j++)
                    encrypted[i, j] = 'x';


            int current_row = 0, current_column = 0;
            int plainText_length = plain_text_without_spaces.Length;


            for (int i = 0; i < plainText_length; i++)
            {
                encrypted[current_row, current_column] = plain_text_without_spaces[i];
                current_column++;
                if (current_column == num_of_columns)
                {
                    current_column = 0;
                    current_row++;
                }
            }


            StringBuilder result = new StringBuilder();
            Dictionary<int, int> keyMap = new Dictionary<int, int>();
            for (int i = 0; i < key.Count; i++)
            {
                keyMap[key.Min()] = key.IndexOf(key.Min());
                key[key.IndexOf(key.Min())] = 999999999;
            }
            for (int i = 1; i <= keyMap.Count; i++)
                for (int j = 0; j < num_of_rows; j++)
                    result.Append(encrypted[j, keyMap[i]]);
            return result.ToString();
            //throw new NotImplementedException();
        }
    }

}
