using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {

        public static int[,] GetInverseMatrix(int[,] matrix)
        {
            int n = matrix.GetLength(0);
            int[,] inverseMatrix = new int[n, n];

            // Compute the determinant
            int det = matrix[0, 0] * (matrix[1, 1] * matrix[2, 2] - matrix[1, 2] * matrix[2, 1]) -
                      matrix[0, 1] * (matrix[1, 0] * matrix[2, 2] - matrix[1, 2] * matrix[2, 0]) +
                      matrix[0, 2] * (matrix[1, 0] * matrix[2, 1] - matrix[1, 1] * matrix[2, 0]);

            if (det == 0)
                throw new InvalidOperationException("Matrix is singular");

            // Compute the adjugate matrix
            inverseMatrix[0, 0] = (matrix[1, 1] * matrix[2, 2] - matrix[1, 2] * matrix[2, 1]);
            inverseMatrix[0, 1] = (matrix[0, 2] * matrix[2, 1] - matrix[0, 1] * matrix[2, 2]);
            inverseMatrix[0, 2] = (matrix[0, 1] * matrix[1, 2] - matrix[0, 2] * matrix[1, 1]);
            inverseMatrix[1, 0] = (matrix[1, 2] * matrix[2, 0] - matrix[1, 0] * matrix[2, 2]);
            inverseMatrix[1, 1] = (matrix[0, 0] * matrix[2, 2] - matrix[0, 2] * matrix[2, 0]);
            inverseMatrix[1, 2] = (matrix[0, 2] * matrix[1, 0] - matrix[0, 0] * matrix[1, 2]);
            inverseMatrix[2, 0] = (matrix[1, 0] * matrix[2, 1] - matrix[1, 1] * matrix[2, 0]);
            inverseMatrix[2, 1] = (matrix[0, 1] * matrix[2, 0] - matrix[0, 0] * matrix[2, 1]);
            inverseMatrix[2, 2] = (matrix[0, 0] * matrix[1, 1] - matrix[0, 1] * matrix[1, 0]);

            // Multiply each element by the determinant
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    inverseMatrix[i, j] *= det;
                }
            }

            return inverseMatrix;
        }



        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {

            int plainTextlength = plainText.Count;
            int cipherTextlength = cipherText.Count;
            int[,] matrixPlain = new int[2, plainTextlength / 2];
            int[,] matrixcipher = new int[2, cipherTextlength/2];

            int col1 = -1, col2 = -1;
            int counter = 0;
            for (int i = 0; i < plainTextlength / 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    matrixPlain[j, i] = plainText[counter];
                    matrixcipher[j, i] = cipherText[counter++];
                }
            }
            int [,]subplainmatrix = new int[2, 2];
            int [,] inversePlain = new int[2, 2];
            inversePlain[0, 0] = 0;
            inversePlain[0, 1] = 0;
            inversePlain[1, 0] = 0;
            inversePlain[1, 1] = 0;
            for (int i=0; i< plainTextlength / 2; i++)
            {
                for(int j= i+1; j < plainTextlength / 2; j++)
                {
                    if ((matrixPlain[0,i]* matrixPlain[1,j] - matrixPlain[0,j]* matrixPlain[1, i]) == 0 ||
                        (((matrixPlain[0, i] * matrixPlain[1, j] - matrixPlain[0, j] * matrixPlain[1, i])+(26000))%26) %2 == 0)
                    {
                        continue;
                    }
                    subplainmatrix[0, 0] = matrixPlain[0, i];
                    subplainmatrix[0, 1] = matrixPlain[0, j];
                    subplainmatrix[1, 0] = matrixPlain[1, i];
                    subplainmatrix[1, 1] = matrixPlain[1, j];

                    int determent = (((subplainmatrix[0, 0] * subplainmatrix[1, 1] - subplainmatrix[0, 1] * subplainmatrix[1, 0]) + (26000)) % 26);
                    col1 = i;
                    col2= j;
                    int mul_inverse=2;
                    while (true)
                    {
                        if(determent* mul_inverse % 26 == 1)
                        {
                            break;
                        }
                        mul_inverse++;
                    }
                    inversePlain[0, 0] = mul_inverse * subplainmatrix[1, 1];
                    inversePlain[0, 1] = -mul_inverse * subplainmatrix[0, 1];
                    inversePlain[1, 0] = -mul_inverse * subplainmatrix[1, 0];
                    inversePlain[1, 1] = mul_inverse * subplainmatrix[0, 0];
                    break;
                }
            }
            if (inversePlain[0, 0] == 0&& inversePlain[0, 1] == 0&& inversePlain[1, 0] == 0&& inversePlain[1, 1] == 0)
                throw new InvalidAnlysisException();

            int[,] subciphermatrix = new int[2, 2];
            subciphermatrix[0,0] = matrixcipher[0, col1];
            subciphermatrix[0,1] = matrixcipher[0, col2];
            subciphermatrix[1,0] = matrixcipher[1, col1];
            subciphermatrix[1,1] = matrixcipher[1, col2];

            
            int[,] keyMatrix = new int[2,2];
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    for (int k = 0; k < 2; k++)
                    {
                        keyMatrix[i, j] += subciphermatrix[i, k] * inversePlain[k, j];
                    }
                }
            }
            List<int> theKey = new List<int>();
            theKey.Add(keyMatrix[0,0]%26);
            theKey.Add(keyMatrix[0,1]%26);
            theKey.Add(keyMatrix[1,0]%26);
            theKey.Add(keyMatrix[1,1]%26);

            return theKey;
            //throw new NotImplementedException();
        }



        public string Analyse(string plainText, string cipherText)
        {
            List<int> lstPlainText = plainText.ToLower().Select(c => c - 'a').ToList();
            List<int> lstCipherText = cipherText.ToLower().Select(c => c - 'a').ToList();
            List<int> key = Analyse(lstPlainText, lstCipherText);
            string alpha = "abcdefghijklmnopqrstuvwxyz";
            Dictionary<char, int> dict = new Dictionary<char, int>();
            for (int i = 0; i < 26; i++)
                dict[alpha[i]] = i;
            string key_letters = "";
            foreach (int num in key)
            {
                foreach (KeyValuePair<char, int> pair in dict)
                {
                    if (pair.Value == num)
                    {
                        key_letters += pair.Key;
                        break;
                    }
                }
            }
            return key_letters;
            //throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<int> plainText = new List<int>();
            List<int> list = new List<int>();
            int[,] inverse_key;
            int det; 
            double inv_det;
            if (key.Count == 4)
            {
                det = key[0] * key[3] - key[1] * key[2];

                inverse_key = new int[2, 2];
                inverse_key[0, 0] = (key[3] / det);
                inverse_key[0, 1] = (-key[1] / det);
                inverse_key[1, 0] = (-key[2] / det);
                inverse_key[1, 1] = (key[0] / det);

                if (inverse_key[0, 0] == 0 && inverse_key[0, 1] == 0 && inverse_key[1, 0] == 0 && inverse_key[1, 1] == 0)
                    throw new Exception();
                int num_of_columns = cipherText.Count / 2;
                int[,] matrix = new int[2, num_of_columns];
                int current_row = 0, current_column = 0;
                int plain_text_count = cipherText.Count;
                for (int i = 0; i < plain_text_count; i++)
                {
                    if (2 == current_row)
                    {
                        current_row = 0;
                        current_column++;
                        matrix[current_row, current_column] = cipherText[i];
                        current_row++;
                    }
                    else
                    {
                        matrix[current_row, current_column] = cipherText[i];
                        current_row++;
                    }
                }
                List<int> lst = new List<int>();
                int result = 0;
                for (int i = 0; i < num_of_columns; i++)
                {
                    for (int j = 0; j < 2; j++)
                    {
                        for (int k = 0; k < 2; k++)
                        {
                            result += inverse_key[j, k] * matrix[k, i];
                        }
                        lst.Add((result + 676) % 26);
                        result = 0;
                    }
                }
                return lst;
            }
            //else if (key.Count == 9)
            //{
            //    int[,] keyMatrix = new int[3, 3];
            //    for (int i = 0; i < 3; i++)
            //    {
            //        for (int j = 0; j < 3; j++)
            //        {
            //            keyMatrix[i, j] = key[i * 3 + j];
            //        }
            //    }
            //    int[,] inverseKeyMatrix = GetInverseMatrix(keyMatrix);
            //    int numColumns = cipherText.Count / 3;
            //    int[,] cipherMatrix = new int[3, numColumns];
            //    int row = 0, column = 0;
            //    for (int i = 0; i < cipherText.Count; i++)
            //    {
            //        if (row == 3)
            //        {
            //            row = 0;
            //            column++;
            //        }
            //        cipherMatrix[row, column] = cipherText[i];
            //        row++;
            //    }
            //    for (int i = 0; i < numColumns; i++)
            //    {
            //        for (int j = 0; j < 3; j++)
            //        {
            //            int result = 0;
            //            for (int k = 0; k < 3; k++)
            //            {
            //                result += inverseKeyMatrix[j, k] * cipherMatrix[k, i];
            //            }
            //            int decryptedChar = (result * 3) % 26;
            //            if (decryptedChar < 0)
            //                decryptedChar += 26;
            //            plainText.Add(decryptedChar);
            //        }
            //    }
            //}
            //else
            //{
            //    throw new Exception("Invalid key size");
            //}
            return plainText;
        //throw new NotImplementedException();
    }

        public string Decrypt(string cipherText, string key)
        {
           throw new NotImplementedException();
        }
        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int key_dimention = (int)Math.Sqrt(key.Count);
            int[,] key_matrix = new int[key_dimention, key_dimention];
            for (int i = 0; i < key_dimention; i++)
                for (int j = 0; j < key_dimention; j++)
                    key_matrix[i, j] = key[i * key_dimention + j];
            int num_of_columns = plainText.Count / key_dimention;
            int[,] matrix = new int[key_dimention, num_of_columns];
            int current_row = 0, current_column = 0;
            int plain_text_count = plainText.Count;
            for (int i = 0; i < plain_text_count; i++)
            {
                if (key_dimention == current_row)
                {
                    current_row = 0;
                    current_column++;
                    matrix[current_row, current_column] = plainText[i];
                    current_row++;
                }
                else
                {
                    matrix[current_row, current_column] = plainText[i];
                    current_row++;
                }
            }
            List<int> list = new List<int>();
            int result = 0;
            for (int i = 0; i < num_of_columns; i++)
            {
                for (int j = 0; j < key_dimention; j++)
                {
                    for (int k = 0; k < key_dimention; k++)
                    {
                        result += key_matrix[j, k] * matrix[k, i];
                    }
                    list.Add(result % 26);
                    result = 0;
                }
            }
            return list;
            //throw new NotImplementedException();
        }
        public string Encrypt(string plainText, string key)
        {    
            throw new NotImplementedException();
        }
        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            throw new NotImplementedException();
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}






















//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Text;
//using System.Threading.Tasks;

//namespace SecurityLibrary
//{
//    /// <summary>
//    /// The List<int> is row based. Which means that the key is given in row based manner.
//    /// </summary>
//    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
//    {
//        public List<int> Analyse(List<int> plainText, List<int> cipherText)
//        {
//            throw new NotImplementedException();
//        }

//        public string Analyse(string plainText, string cipherText)
//        {
//            throw new NotImplementedException();
//        }

//        public List<int> Decrypt(List<int> cipherText, List<int> key)
//        {
//            throw new NotImplementedException();
//        }

//        public string Decrypt(string cipherText, string key)
//        {
//            throw new NotImplementedException();
//        }

//        public List<int> Encrypt(List<int> plainText, List<int> key)
//        {
//            Dictionary<char, int> d = new Dictionary<char, int>();
//            string alpha = "abcdefghijklmnopqrstuvwxyz";
//            for (int i = 0; i < 26; i++)
//            {
//                d[alpha[i]] = i;
//            }
//            int m = (int)Math.Sqrt(key.Count);
//            int[,] matrix = new int[m, plainText.Count / key.Count];



//            int current_row = 0, current_column = 0;
//            for (int i = 0; i < plainText.Count; i++)
//            {
//                if (m == current_row)
//                {
//                    current_row = 0;
//                    current_column++;
//                    matrix[current_row, current_column] = plainText[i];
//                    current_row++;
//                }
//                else
//                {
//                    matrix[current_row, current_column] = plainText[i];
//                    current_row++;
//                }
//            }

//            int[,] key_matrix = new int[m, m];
//            current_row = 0; current_column = 0;
//            for (int i = 0; i < key.Count; i++)
//            {
//                if (m == current_row)
//                {
//                    current_row = 0;
//                    current_column++;
//                    key_matrix[current_row, current_column] = key[i];
//                    current_row++;
//                }
//                else
//                {
//                    key_matrix[current_row, current_column] = key[i];
//                    current_row++;
//                }
//            }





//            List<int> y = new List<int>();
//            int[,] result = new int[m, 1];
//            for (int i = 0; i < m; i++)
//            {
//                for (int j = 0; j < 1; j++)
//                {
//                    for (int k = 0; k < m; k++)
//                    {
//                        result[i, j] += key_matrix[k, j] * matrix[i, k];
//                    }
//                    result[i, j] = result[i, j] % 26;

//                    for (int ii = 0; ii < m; ii++)
//                    {
//                        y.Add(result[ii, 0]);
//                    }
//                }
//            }

//            return y;






//            throw new NotImplementedException();
//        }

//        public string Encrypt(string plainText, string key)
//        {
//            throw new NotImplementedException();
//        }

//        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
//        {
//            throw new NotImplementedException();
//        }

//        public string Analyse3By3Key(string plain3, string cipher3)
//        {
//            throw new NotImplementedException();
//        }
//    }
//}
