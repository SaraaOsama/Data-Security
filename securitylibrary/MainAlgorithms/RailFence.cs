using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            // return 0;
            bool check = true;
            int counter = 1;
            while (check && counter < plainText.Length)
            {
                if (Encrypt(plainText, counter).Equals(cipherText, StringComparison.InvariantCultureIgnoreCase))
                    check = false;
                counter++;
            }
            return counter - 1;
            //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, int key)
        {
            
            int num_of_columns = cipherText.Length % key == 0 ? cipherText.Length / key : (cipherText.Length / key) + 1;
            char[,] decrypted = new char[key, num_of_columns];
            int plainText_length = cipherText.Length;
            int counter = 0;
            for (int i = 0; i < key; i++) {
                for (int j = 0; j < num_of_columns; j++) {
                    if(counter< plainText_length)
                        decrypted[i,j]= cipherText[counter++];
                }
            }

            StringBuilder temp = new StringBuilder();
            for (int i = 0; i < num_of_columns; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    temp.Append(decrypted[j, i]);
                }
            }

            return temp.ToString();
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, int key)
        {
            StringBuilder temp = new StringBuilder();
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] == ' ')
                {
                    continue;
                }
                else
                {
                    temp.Append(plainText[i]);
                }
            }
            string plain_text_without_spaces = temp.ToString();
            int num_of_columns = plain_text_without_spaces.Length % key == 0 ? plain_text_without_spaces.Length / key : (plain_text_without_spaces.Length / key) + 1;
            char[,] encrypted = new char[key, num_of_columns];
            int current_row = 0, current_column = 0;
            int plainText_length = plain_text_without_spaces.Length;
            for (int i = 0; i < plainText_length; i++) {
                if (key == current_row )
                {
                    current_row = 0;
                    current_column++;
                    encrypted[current_row, current_column] = plain_text_without_spaces[i];
                    current_row++;
                }
                else {
                    encrypted[current_row,current_column] = plain_text_without_spaces[i];
                    current_row++;
                }
            }
            StringBuilder x = new StringBuilder();
            for (int i = 0; i < key; i++) {
                for (int j = 0; j < num_of_columns; j++) {
                        x.Append(encrypted[i, j]);
                }
             }
            return x.ToString();
            //throw new NotImplementedException();
        }
        
    }
}
