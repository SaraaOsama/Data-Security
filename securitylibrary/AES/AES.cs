using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        string[,] s_box = new string[,]{
                {" ","0" , "1" ,"2" , "3" , "4" , "5" , "6" ,"7","8","9","a","b","c","d","e","f"},
                {"0" , "63" , "7c" , "77" , "7b" , "f2" ,"6b"  , "6f" , "c5" , "30" , "01" , "67" , "2b" , "fe" , "d7" , "ab" , "76" },
                {"1" , "ca" , "82" , "c9" , "7d" , "fa" ,"59"  , "47" , "f0" , "ad" , "d4" , "a2" , "af" , "9c" , "a4" , "72" , "c0" },
                {"2" , "b7" , "fd" , "93" , "26" , "36" ,"3f"  , "f7" , "cc" , "34" , "a5" , "e5" , "f1" , "71" , "d8" , "31" , "15" },
                {"3" , "04" , "c7" , "23" , "c3" , "18" ,"96"  , "05" , "9a" , "07" , "12" , "80" , "e2" , "eb" , "27" , "b2" , "75" },
                {"4" , "09" , "83" , "2c" , "1a" , "1b" ,"6e"  , "5a" , "a0" , "52" , "3b" , "d6" , "b3" , "29" , "e3" , "2f" , "84" },
                {"5" , "53" , "d1" , "00" , "ed" , "20" ,"fc"  , "b1" , "5b" , "6a" , "cb" , "be" , "39" , "4a" , "4c" , "58" , "cf" },
                {"6" , "d0" , "ef" , "aa" , "fb" , "43" ,"4d"  , "33" , "85" , "45" , "f9" , "02" , "7f" , "50" , "3c" , "9f" , "a8" },
                {"7" , "51" , "a3" , "40" , "8f" , "92" ,"9d"  , "38" , "f5" , "bc" , "b6" , "da" , "21" , "10" , "ff" , "f3" , "d2" },
                {"8" , "cd" , "0c" , "13" , "ec" , "5f" ,"97"  , "44" , "17" , "c4" , "a7" , "7e" , "3d" , "64" , "5d" , "19" , "73" },
                {"9" , "60" , "81" , "4f" , "dc" , "22" ,"2a"  , "90" , "88" , "46" , "ee" , "b8" , "14" , "de" , "5e" , "0b" , "db" },
                {"a" , "e0" , "32" , "3a" , "0a" , "49" ,"06"  , "24" , "5c" , "c2" , "d3" , "ac" , "62" , "91" , "95" , "e4" , "79" },
                {"b" , "e7" , "c8" , "37" , "6d" , "8d" ,"d5"  , "4e" , "a9" , "6c" , "56" , "f4" , "ea" , "65" , "7a" , "ae" , "08" },
                {"c" , "ba" , "78" , "25" , "2e" , "1c" ,"a6"  , "b4" , "c6" , "e8" , "dd" , "74" , "1f" , "4b" , "bd" , "8b" , "8a" },
                {"d" , "70" , "3e" , "b5" , "66" , "48" ,"03"  , "f6" , "0e" , "61" , "35" , "57" , "b9" , "86" , "c1" , "1d" , "9e" },
                {"e" , "e1" , "f8" , "98" , "11" , "69" ,"d9"  , "8e" , "94" , "9b" , "1e" , "87" , "e9" , "ce" , "55" , "28" , "df" },
                {"f" , "8c" , "a1" , "89" , "0d" , "bf" ,"e6"  , "42" , "68" , "41" , "99" , "2d" , "0f" , "b0" , "54" , "bb" , "16" } };
        public string[,] subytes(string[,] matrix)
        {
            string[,] result = new string[4, 4];
            for(int i = 0;i<4; i++)
            {
                for(int j = 0;j<4; j++)
                {
                    for(int i2=1; i2 <= 16; i2++)
                    {
                        if(matrix[i, j][0].ToString() == s_box[i2, 0])
                        {
                            for(int j2=1; j2<=16; j2++)
                            {
                                if (matrix[i, j][1].ToString() == s_box[0, j2])
                                {
                                    result[i,j] = s_box[i2, j2];
                                }
                            }
                        }
                    }
                    
                }
            }
            return result;

        }
        public string ConvertBinaryToHex(List<string> groupedBinary)
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
        public string HexStringToBinary(string hexString)
        {
            //string hexWithoutPrefix = hexString;
            ulong intValue = ulong.Parse(hexString, System.Globalization.NumberStyles.HexNumber);
            string binaryString = Convert.ToString((long)intValue, 2).PadLeft(hexString.Length * 4, '0');
            return binaryString;
        }
        public List<string> key_schedule(string[,] key)
        {
            List<string> returned_list = new List<string>();
            string[,] rcon = new string[,] {
                {"01","02","04","08","10","20","40","80","1b","36" },
                {"00","00","00","00","00","00","00","00","00","00" },
                {"00","00","00","00","00","00","00","00","00","00" },
                {"00","00","00","00","00","00","00","00","00","00" }
            };

            returned_list.Add(key[0, 0] + key[1, 0] + key[2, 0] + key[3, 0]);
            returned_list.Add(key[0, 1] + key[1, 1] + key[2, 1] + key[3, 1]);
            returned_list.Add(key[0, 2] + key[1, 2] + key[2, 2] + key[3, 2]);
            returned_list.Add(key[0, 3] + key[1, 3] + key[2, 3] + key[3, 3]);



            string[,] result = new string[4, 4];
            int counter_of_rcon = 0;
            string temp_xor_2 = "";
            for (int i = 4; i < 44; i++)
            {
                //for(int j= 0; j < 4; j++)
                //{


                if (i % 4 == 0)
                {
                    temp_xor_2 = "";
                    string[,] temp = new string[4, 1];

                    temp[0, 0] = (returned_list[i - 1][0].ToString() + returned_list[i - 1][1].ToString()).ToLower();
                    temp[1, 0] = (returned_list[i - 1][2].ToString() + returned_list[i - 1][3].ToString()).ToLower();
                    temp[2, 0] = (returned_list[i - 1][4].ToString() + returned_list[i - 1][5].ToString()).ToLower();
                    temp[3, 0] = (returned_list[i - 1][6].ToString() + returned_list[i - 1][7].ToString()).ToLower();




                    string temp1 = temp[0, 0];
                    for (int k = 0; k < 3; k++)
                    {
                        temp[k, 0] = temp[k + 1, 0];
                    }
                    temp[3, 0] = temp1;
                    string[,] temp_after_subytes = new string[4, 1];

                    for (int k = 0; k < 4; k++)
                    {
                        for (int i2 = 1; i2 <= 16; i2++)
                        {
                            if (temp[k, 0][0].ToString() == s_box[i2, 0])
                            {
                                for (int j2 = 1; j2 <= 16; j2++)
                                {
                                    if (temp[k, 0][1].ToString() == s_box[0, j2])
                                    {
                                        temp_after_subytes[k, 0] = s_box[i2, j2];
                                        break;
                                    }
                                }
                                break;
                            }
                        }
                    }
                    string[] first_column_from_rcon = new string[4];
                    for (int k = 0; k < 4; k++)
                    {
                        first_column_from_rcon[k] = rcon[k, counter_of_rcon];
                    }
                    counter_of_rcon++;



                    string[,] first_column_from_key = new string[4, 1];
                    //for (int k = 0; k < 4; k++)
                    //{
                    //    first_column_from_key[k, 0] = key[k, 0];
                    first_column_from_key[0, 0] = returned_list[i - 4][0].ToString() + returned_list[i - 4][1].ToString();
                    first_column_from_key[1, 0] = returned_list[i - 4][2].ToString() + returned_list[i - 4][3].ToString();
                    first_column_from_key[2, 0] = returned_list[i - 4][4].ToString() + returned_list[i - 4][5].ToString();
                    first_column_from_key[3, 0] = returned_list[i - 4][6].ToString() + returned_list[i - 4][7].ToString();



                    //}
                    string temp_after_subytes_string = "";
                    for (int k = 0; k < 4; k++)
                    {
                        temp_after_subytes_string += temp_after_subytes[k, 0];

                    }
                    temp_after_subytes_string = HexStringToBinary(temp_after_subytes_string);
                    string first_column_from_rcon_string = "";
                    for (int k = 0; k < 4; k++)
                    {
                        first_column_from_rcon_string += first_column_from_rcon[k];
                    }
                    first_column_from_rcon_string = HexStringToBinary(first_column_from_rcon_string);

                    string temp_string = "";
                    for (int k = 0; k < 4; k++)
                    {
                        temp_string += first_column_from_key[k, 0];
                    }
                    temp_string = HexStringToBinary(temp_string);
                    string temp_xor_1 = "";

                    for (int k = 0; k < temp_string.Length; k++)
                    {
                        temp_xor_1 += int.Parse(temp_string[k].ToString()) ^ int.Parse(temp_after_subytes_string[k].ToString());
                    }
                    for (int k = 0; k < first_column_from_rcon_string.Length; k++)
                    {
                        temp_xor_2 += int.Parse(temp_xor_1[k].ToString()) ^ int.Parse(first_column_from_rcon_string[k].ToString());
                    }

                    List<string> list = new List<string>();
                    list.Add(temp_xor_2[0].ToString() + temp_xor_2[1].ToString() + temp_xor_2[2].ToString() + temp_xor_2[3].ToString());
                    list.Add(temp_xor_2[4].ToString() + temp_xor_2[5].ToString() + temp_xor_2[6].ToString() + temp_xor_2[7].ToString());
                    list.Add(temp_xor_2[8].ToString() + temp_xor_2[9].ToString() + temp_xor_2[10].ToString() + temp_xor_2[11].ToString());
                    list.Add(temp_xor_2[12].ToString() + temp_xor_2[13].ToString() + temp_xor_2[14].ToString() + temp_xor_2[15].ToString());
                    list.Add(temp_xor_2[16].ToString() + temp_xor_2[17].ToString() + temp_xor_2[18].ToString() + temp_xor_2[19].ToString());
                    list.Add(temp_xor_2[20].ToString() + temp_xor_2[21].ToString() + temp_xor_2[22].ToString() + temp_xor_2[23].ToString());
                    list.Add(temp_xor_2[24].ToString() + temp_xor_2[25].ToString() + temp_xor_2[26].ToString() + temp_xor_2[27].ToString());
                    list.Add(temp_xor_2[28].ToString() + temp_xor_2[29].ToString() + temp_xor_2[30].ToString() + temp_xor_2[31].ToString());
                    string added = ConvertBinaryToHex(list).ToLower();
                    returned_list.Add(added);

                }
                else
                {

                    string second_column = "";
                    string second_column_of_key = returned_list[i - 4];

                    second_column_of_key = HexStringToBinary(second_column_of_key);
                    temp_xor_2 = returned_list[i - 1];
                    temp_xor_2 = HexStringToBinary(temp_xor_2);
                    for (int k = 0; k < temp_xor_2.Length; k++)
                    {
                        second_column += (int.Parse(temp_xor_2[k].ToString()) ^ int.Parse(second_column_of_key[k].ToString())).ToString();
                    }

                    //string third_column_of_key = key[0, 2];
                    //third_column_of_key += key[1, 2];
                    //third_column_of_key += key[2, 2];
                    //third_column_of_key += key[3, 2];
                    //third_column_of_key = HexStringToBinary(third_column_of_key);
                    //string third_column = "";
                    //for (int k = 0; k < second_column.Length; k++)
                    //{
                    //    third_column += (int.Parse(second_column[k].ToString()) ^ int.Parse(third_column_of_key[k].ToString())).ToString();
                    //}


                    //string fourth_column_of_key = key[0, 3];
                    //fourth_column_of_key += key[1, 3];
                    //fourth_column_of_key += key[2, 3];
                    //fourth_column_of_key += key[3, 3];
                    //fourth_column_of_key = HexStringToBinary(fourth_column_of_key);
                    //string fourth_column = "";
                    //for (int k = 0; k < third_column.Length; k++)
                    //{
                    //    fourth_column += (int.Parse(third_column[k].ToString()) ^ int.Parse(fourth_column_of_key[k].ToString())).ToString();
                    //}

                    List<string> list = new List<string>();
                    //list.Add(temp_xor_2[0].ToString() + temp_xor_2[1].ToString() + temp_xor_2[2].ToString() + temp_xor_2[3].ToString());
                    //list.Add(temp_xor_2[4].ToString() + temp_xor_2[5].ToString() + temp_xor_2[6].ToString() + temp_xor_2[7].ToString());
                    list.Add(second_column[0].ToString() + second_column[1].ToString() + second_column[2].ToString() + second_column[3].ToString());
                    list.Add(second_column[4].ToString() + second_column[5].ToString() + second_column[6].ToString() + second_column[7].ToString());
                    list.Add(second_column[8].ToString() + second_column[9].ToString() + second_column[10].ToString() + second_column[11].ToString());
                    list.Add(second_column[12].ToString() + second_column[13].ToString() + second_column[14].ToString() + second_column[15].ToString());
                    list.Add(second_column[16].ToString() + second_column[17].ToString() + second_column[18].ToString() + second_column[19].ToString());
                    list.Add(second_column[20].ToString() + second_column[21].ToString() + second_column[22].ToString() + second_column[23].ToString());
                    list.Add(second_column[24].ToString() + second_column[25].ToString() + second_column[26].ToString() + second_column[27].ToString());
                    list.Add(second_column[28].ToString() + second_column[29].ToString() + second_column[30].ToString() + second_column[31].ToString());

                    //list.Add(third_column[0].ToString() + third_column[1].ToString() + third_column[2].ToString() + third_column[3].ToString());
                    //list.Add(third_column[4].ToString() + third_column[5].ToString() + third_column[6].ToString() + third_column[7].ToString());
                    //list.Add(fourth_column[0].ToString() + fourth_column[1].ToString() + fourth_column[2].ToString() + fourth_column[3].ToString());
                    //list.Add(fourth_column[4].ToString() + fourth_column[5].ToString() + fourth_column[6].ToString() + fourth_column[7].ToString());
                    string added = ConvertBinaryToHex(list);
                    returned_list.Add(added);
                }
                //}




            }


            for (int i = 0; i < returned_list.Count; i++)
            {
                returned_list[i] = returned_list[i].ToLower();
            }
            return returned_list;

        }
        public  byte[,] shiftRowsInverse(byte[,] data)
        {
            byte temp1, temp2, temp3;
            temp1 = data[1, 3];
            for (int i = 3; i > 0; i--)
            {
                data[1, i] = data[1, i - 1];
            }
            data[1, 0] = temp1;

            temp1 = data[2, 2];
            temp2 = data[2, 3];
            data[2, 3] = data[2, 1];
            data[2, 2] = data[2, 0];
            data[2, 1] = temp2;
            data[2, 0] = temp1;
            temp1 = data[3, 1];
            temp2 = data[3, 2];
            temp3 = data[3, 3];
            data[3, 3] = data[3, 0];
            data[3, 0] = temp1;
            data[3, 1] = temp2;
            data[3, 2] = temp3;
            return data;
        }
        string[,] InverseSubytes(string[,] matrix)
        {

            Dictionary<string, string> D = new Dictionary<string, string>();
            string[,] result = new string[4, 4];
            for (int i = 1; i < s_box.GetLength(0); i++)
            {
                for (int j = 1; j < s_box.GetLength(1); j++)
                {
                    D[s_box[i, j]] = s_box[i, 0].ToString() + s_box[0, j].ToString();
                }
            }
            for (int i = 0; i < matrix.GetLength(0); i++)
            {
                for (int j = 0; j < matrix.GetLength(1); j++)
                {
                    result[i, j] = D[matrix[i, j].ToLower()];
                }
            }
            return result;
        }
        string toInteg(string s)
        {
            int integerValue = Convert.ToInt32(s, 16);
            return integerValue.ToString();
        }
        public string[,] AddRoundKey(string[,] data, string[,] RoundKey)
        {
            string[,] output = new string[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    data[i, j] = toInteg(data[i, j]);
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    RoundKey[i, j] = toInteg(RoundKey[i, j]);
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    output[i, j] = (int.Parse(data[i, j]) ^ int.Parse(RoundKey[i, j])).ToString("x2");
                }
            }
            return output;
        }
        byte[,] mixColumns(byte[,] b)
        {
            byte[,] c = new byte[,]
            {
        {0x02,0x03,0x01,0x01 },
        {0x01,0x02,0x03,0x01 },
        {0x01,0x01,0x02,0x03 },
        {0x03,0x01,0x01,0x02 }
            };
            byte[,] ans = new byte[4, 4];
            byte[] curColumn = new byte[4];
            byte[] curColumnAns = new byte[4];
            for (int o = 0; o < 4; o++)
            {
                for (int i = 0; i < 4; i++)
                {
                    curColumn[i] = b[i, o];
                }
                for (int i = 0; i < 4; i++)
                {
                    byte[] curRow = new byte[4];
                    for (int j = 0; j < 4; j++)
                        curRow[j] = c[i, j];
                    byte ians = multiRows(curColumn, curRow);
                    curColumnAns[i] = ians;
                }
                for (int i = 0; i < 4; i++)
                {
                    ans[i, o] = curColumnAns[i];
                }
            }
            return ans;
        }
        byte multiRows(byte[] a, byte[] b)
        {
            byte[] ans = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                if (b[i] == 0x01)
                    ans[i] = a[i];
                else if (b[i] == 0x02)
                {
                    ans[i] = c_2(a[i]);
                }
                else
                {
                    ans[i] = c_3(a[i]);
                }
            }
            byte fans = 0;
            for (int i = 0; i < 4; i++)
            {
                fans = (byte)(ans[i] ^ fans);
            }
            return fans;
        }
        byte c_2(byte a)
        {
            byte leftmostBit = (byte)(a & 0x80);
            if (leftmostBit == 0)
            {
                byte ians = (byte)(a << 1);
                return ians;
            }
            else
            {
                byte shiftLeft = (byte)(a << 1);
                byte result = (byte)(shiftLeft ^ 0x1B);
                return result;
            }
        }
        byte c_3(byte a)
        {
            byte b1 = c_2(a);
            byte b2 = a;
            byte b3 = (byte)(b1 ^ a);
            return b3;
        }
        public byte[,] shiftRows(byte[,] data)
        {
            byte temp1, temp2, temp3;
            temp1 = data[1, 0];
            for (int i = 0; i < 3; i++)
            {
                data[1, i] = data[1, i + 1];
            }
            data[1, 3] = temp1;

            temp1 = data[2, 0];
            temp2 = data[2, 1];
            for (int j = 0; j < 2; j++)
            {
                data[2, j] = data[2, j + 2];
            }
            data[2, 2] = temp1;
            data[2, 3] = temp2;

            temp1 = data[3, 0];
            temp2 = data[3, 1];
            temp3 = data[3, 2];
            for (int j = 0; j < 1; j++)
            {
                data[3, j] = data[3, j + 3];
            }
            data[3, 1] = temp1;
            data[3, 2] = temp2;
            data[3, 3] = temp3;

            return data;
        }
        public byte[,] ConvertHexStringsToBytes(string[,] hexStrings)
        {
            int rows = hexStrings.GetLength(0);
            int cols = hexStrings.GetLength(1);

            byte[,] result = new byte[rows, cols];

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    // Convert each hexadecimal string to byte
                    result[i, j] = Convert.ToByte(hexStrings[i, j], 16);
                }
            }

            return result;
        }
        public string[,] ConvertBytesToHexStrings(byte[,] byteArray)
        {
            int rows = byteArray.GetLength(0);
            int cols = byteArray.GetLength(1);

            string[,] hexStrings = new string[rows, cols];

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    // Convert each byte to hexadecimal string
                    hexStrings[i, j] = byteArray[i, j].ToString("X2");
                }
            }

            return hexStrings;
        }


        static byte[,] InverseMixColumns(byte[,] state)
        {
            byte[,] result = new byte[4, 4];

            for (int c = 0; c < 4; c++)
            {
                result[0, c] = (byte)(Multiply(0x0E, state[0, c]) ^ Multiply(0x0B, state[1, c]) ^ Multiply(0x0D, state[2, c]) ^ Multiply(0x09, state[3, c]));
                result[1, c] = (byte)(Multiply(0x09, state[0, c]) ^ Multiply(0x0E, state[1, c]) ^ Multiply(0x0B, state[2, c]) ^ Multiply(0x0D, state[3, c]));
                result[2, c] = (byte)(Multiply(0x0D, state[0, c]) ^ Multiply(0x09, state[1, c]) ^ Multiply(0x0E, state[2, c]) ^ Multiply(0x0B, state[3, c]));
                result[3, c] = (byte)(Multiply(0x0B, state[0, c]) ^ Multiply(0x0D, state[1, c]) ^ Multiply(0x09, state[2, c]) ^ Multiply(0x0E, state[3, c]));
            }

            return result;
        }

        static byte Multiply(byte a, byte b)
        {
            byte result = 0;
            byte highBitSet;

            for (int i = 0; i < 8; i++)
            {
                if ((b & 1) == 1)
                    result ^= a;

                highBitSet = (byte)(a & 0x80);
                a <<= 1;
                if (highBitSet == 0x80)
                    a ^= 0x1B;

                b >>= 1;
            }

            return result;
        }
        public override string Decrypt(string cipherText, string key)
        {
            string[,] ciprherText_matrix = new string[4, 4];
            int current_row = 0, current_column = 0;
            int cipherText_length = cipherText.Length;
            for (int i = 2; i < cipherText_length; i += 2)
            {
                if (4 == current_row)
                {
                    current_row = 0;
                    current_column++;
                    ciprherText_matrix[current_row, current_column] = cipherText[i].ToString() + cipherText[i + 1].ToString();
                    current_row++;
                }
                else
                {
                    ciprherText_matrix[current_row, current_column] = cipherText[i].ToString() + cipherText[i + 1].ToString();
                    current_row++;
                }
            }


            string[,] key_matrix = new string[4, 4];
            current_row = 0; current_column = 0;
            int key_length = key.Length;
            for (int i = 2; i < key_length; i += 2)
            {
                if (4 == current_row)
                {
                    current_row = 0;
                    current_column++;
                    key_matrix[current_row, current_column] = key[i].ToString() + key[i + 1].ToString();
                    current_row++;
                }
                else
                {
                    key_matrix[current_row, current_column] = key[i].ToString() + key[i + 1].ToString();
                    current_row++;
                }
            }
            List<string> key_list = key_schedule(key_matrix);

            string[,] key_0 = new string[4, 4];
            key_0[0, 0] = key_list[40][0].ToString() + key_list[40][1].ToString();
            key_0[1, 0] = key_list[40][2].ToString() + key_list[40][3].ToString();
            key_0[2, 0] = key_list[40][4].ToString() + key_list[40][5].ToString();
            key_0[3, 0] = key_list[40][6].ToString() + key_list[40][7].ToString();

            key_0[0, 1] = key_list[41][0].ToString() + key_list[41][1].ToString();
            key_0[1, 1] = key_list[41][2].ToString() + key_list[41][3].ToString();
            key_0[2, 1] = key_list[41][4].ToString() + key_list[41][5].ToString();
            key_0[3, 1] = key_list[41][6].ToString() + key_list[41][7].ToString();

            key_0[0, 2] = key_list[42][0].ToString() + key_list[42][1].ToString();
            key_0[1, 2] = key_list[42][2].ToString() + key_list[42][3].ToString();
            key_0[2, 2] = key_list[42][4].ToString() + key_list[42][5].ToString();
            key_0[3, 2] = key_list[42][6].ToString() + key_list[42][7].ToString();

            key_0[0, 3] = key_list[43][0].ToString() + key_list[43][1].ToString();
            key_0[1, 3] = key_list[43][2].ToString() + key_list[43][3].ToString();
            key_0[2, 3] = key_list[43][4].ToString() + key_list[43][5].ToString();
            key_0[3, 3] = key_list[43][6].ToString() + key_list[43][7].ToString();

            string[,] add_round_key_0 = AddRoundKey(ciprherText_matrix, key_0);
            ////////////////////////////////////////////////////////////////////////////////
            byte[,] inverse_shift_row_1 = shiftRowsInverse(ConvertHexStringsToBytes(add_round_key_0));
            string[,] inverse_sub_bytes_1 = InverseSubytes(ConvertBytesToHexStrings(inverse_shift_row_1));
            string[,] first_round_key_1 = new string[4, 4];
            first_round_key_1[0, 0] = key_list[36][0].ToString() + key_list[36][1].ToString();
            first_round_key_1[1, 0] = key_list[36][2].ToString() + key_list[36][3].ToString();
            first_round_key_1[2, 0] = key_list[36][4].ToString() + key_list[36][5].ToString();
            first_round_key_1[3, 0] = key_list[36][6].ToString() + key_list[36][7].ToString();

            first_round_key_1[0, 1] = key_list[37][0].ToString() + key_list[37][1].ToString();
            first_round_key_1[1, 1] = key_list[37][2].ToString() + key_list[37][3].ToString();
            first_round_key_1[2, 1] = key_list[37][4].ToString() + key_list[37][5].ToString();
            first_round_key_1[3, 1] = key_list[37][6].ToString() + key_list[37][7].ToString();

            first_round_key_1[0, 2] = key_list[38][0].ToString() + key_list[38][1].ToString();
            first_round_key_1[1, 2] = key_list[38][2].ToString() + key_list[38][3].ToString();
            first_round_key_1[2, 2] = key_list[38][4].ToString() + key_list[38][5].ToString();
            first_round_key_1[3, 2] = key_list[38][6].ToString() + key_list[38][7].ToString();

            first_round_key_1[0, 3] = key_list[39][0].ToString() + key_list[39][1].ToString();
            first_round_key_1[1, 3] = key_list[39][2].ToString() + key_list[39][3].ToString();
            first_round_key_1[2, 3] = key_list[39][4].ToString() + key_list[39][5].ToString();
            first_round_key_1[3, 3] = key_list[39][6].ToString() + key_list[39][7].ToString();
            string[,] add_round_key_1 = AddRoundKey(inverse_sub_bytes_1, first_round_key_1);
            byte[,] inverse_mix_columns_1 = InverseMixColumns(ConvertHexStringsToBytes(add_round_key_1));
            ////////////////////////////////////////////////////////////////////////////////////////////////
            byte[,] inverse_shift_row_2 = shiftRowsInverse(inverse_mix_columns_1);
            string[,] inverse_sub_bytes_2 = InverseSubytes(ConvertBytesToHexStrings(inverse_shift_row_2));
            string[,] second_round_key_2 = new string[4, 4];
            second_round_key_2[0, 0] = key_list[32][0].ToString() + key_list[32][1].ToString();
            second_round_key_2[1, 0] = key_list[32][2].ToString() + key_list[32][3].ToString();
            second_round_key_2[2, 0] = key_list[32][4].ToString() + key_list[32][5].ToString();
            second_round_key_2[3, 0] = key_list[32][6].ToString() + key_list[32][7].ToString();

            second_round_key_2[0, 1] = key_list[33][0].ToString() + key_list[33][1].ToString();
            second_round_key_2[1, 1] = key_list[33][2].ToString() + key_list[33][3].ToString();
            second_round_key_2[2, 1] = key_list[33][4].ToString() + key_list[33][5].ToString();
            second_round_key_2[3, 1] = key_list[33][6].ToString() + key_list[33][7].ToString();

            second_round_key_2[0, 2] = key_list[34][0].ToString() + key_list[34][1].ToString();
            second_round_key_2[1, 2] = key_list[34][2].ToString() + key_list[34][3].ToString();
            second_round_key_2[2, 2] = key_list[34][4].ToString() + key_list[34][5].ToString();
            second_round_key_2[3, 2] = key_list[34][6].ToString() + key_list[34][7].ToString();

            second_round_key_2[0, 3] = key_list[35][0].ToString() + key_list[35][1].ToString();
            second_round_key_2[1, 3] = key_list[35][2].ToString() + key_list[35][3].ToString();
            second_round_key_2[2, 3] = key_list[35][4].ToString() + key_list[35][5].ToString();
            second_round_key_2[3, 3] = key_list[35][6].ToString() + key_list[35][7].ToString();
            string[,] add_round_key_2 = AddRoundKey(inverse_sub_bytes_2, second_round_key_2);
            byte[,] inverse_mix_columns_2 = InverseMixColumns(ConvertHexStringsToBytes(add_round_key_2));
            ///////////////////////////////////////////////////////////////////////////////////////////////////////
            byte[,] inverse_shift_row_3 = shiftRowsInverse(inverse_mix_columns_2);
            string[,] inverse_sub_bytes_3 = InverseSubytes(ConvertBytesToHexStrings(inverse_shift_row_3));
            string[,] second_round_key_3 = new string[4, 4];
            second_round_key_3[0, 0] = key_list[28][0].ToString() + key_list[28][1].ToString();
            second_round_key_3[1, 0] = key_list[28][2].ToString() + key_list[28][3].ToString();
            second_round_key_3[2, 0] = key_list[28][4].ToString() + key_list[28][5].ToString();
            second_round_key_3[3, 0] = key_list[28][6].ToString() + key_list[28][7].ToString();

            second_round_key_3[0, 1] = key_list[29][0].ToString() + key_list[29][1].ToString();
            second_round_key_3[1, 1] = key_list[29][2].ToString() + key_list[29][3].ToString();
            second_round_key_3[2, 1] = key_list[29][4].ToString() + key_list[29][5].ToString();
            second_round_key_3[3, 1] = key_list[29][6].ToString() + key_list[29][7].ToString();

            second_round_key_3[0, 2] = key_list[30][0].ToString() + key_list[30][1].ToString();
            second_round_key_3[1, 2] = key_list[30][2].ToString() + key_list[30][3].ToString();
            second_round_key_3[2, 2] = key_list[30][4].ToString() + key_list[30][5].ToString();
            second_round_key_3[3, 2] = key_list[30][6].ToString() + key_list[30][7].ToString();

            second_round_key_3[0, 3] = key_list[31][0].ToString() + key_list[31][1].ToString();
            second_round_key_3[1, 3] = key_list[31][2].ToString() + key_list[31][3].ToString();
            second_round_key_3[2, 3] = key_list[31][4].ToString() + key_list[31][5].ToString();
            second_round_key_3[3, 3] = key_list[31][6].ToString() + key_list[31][7].ToString();
            string[,] add_round_key_3 = AddRoundKey(inverse_sub_bytes_3, second_round_key_3);
            byte[,] inverse_mix_columns_3 = InverseMixColumns(ConvertHexStringsToBytes(add_round_key_3));
            //////////////////////////////////////////////////////////////////////////////////////////////////
            byte[,] inverse_shift_row_4 = shiftRowsInverse(inverse_mix_columns_3);
            string[,] inverse_sub_bytes_4 = InverseSubytes(ConvertBytesToHexStrings(inverse_shift_row_4));
            string[,] second_round_key_4 = new string[4, 4];
            second_round_key_4[0, 0] = key_list[24][0].ToString() + key_list[24][1].ToString();
            second_round_key_4[1, 0] = key_list[24][2].ToString() + key_list[24][3].ToString();
            second_round_key_4[2, 0] = key_list[24][4].ToString() + key_list[24][5].ToString();
            second_round_key_4[3, 0] = key_list[24][6].ToString() + key_list[24][7].ToString();

            second_round_key_4[0, 1] = key_list[25][0].ToString() + key_list[25][1].ToString();
            second_round_key_4[1, 1] = key_list[25][2].ToString() + key_list[25][3].ToString();
            second_round_key_4[2, 1] = key_list[25][4].ToString() + key_list[25][5].ToString();
            second_round_key_4[3, 1] = key_list[25][6].ToString() + key_list[25][7].ToString();

            second_round_key_4[0, 2] = key_list[26][0].ToString() + key_list[26][1].ToString();
            second_round_key_4[1, 2] = key_list[26][2].ToString() + key_list[26][3].ToString();
            second_round_key_4[2, 2] = key_list[26][4].ToString() + key_list[26][5].ToString();
            second_round_key_4[3, 2] = key_list[26][6].ToString() + key_list[26][7].ToString();

            second_round_key_4[0, 3] = key_list[27][0].ToString() + key_list[27][1].ToString();
            second_round_key_4[1, 3] = key_list[27][2].ToString() + key_list[27][3].ToString();
            second_round_key_4[2, 3] = key_list[27][4].ToString() + key_list[27][5].ToString();
            second_round_key_4[3, 3] = key_list[27][6].ToString() + key_list[27][7].ToString();
            string[,] add_round_key_4 = AddRoundKey(inverse_sub_bytes_4, second_round_key_4);
            byte[,] inverse_mix_columns_4 = InverseMixColumns(ConvertHexStringsToBytes(add_round_key_4));
            ///////////////////////////////////////////////////////////////////////////////////////////////////////////
            byte[,] inverse_shift_row_5 = shiftRowsInverse(inverse_mix_columns_4);
            string[,] inverse_sub_bytes_5 = InverseSubytes(ConvertBytesToHexStrings(inverse_shift_row_5));
            string[,] second_round_key_5 = new string[4, 4];
            second_round_key_5[0, 0] = key_list[20][0].ToString() + key_list[20][1].ToString();
            second_round_key_5[1, 0] = key_list[20][2].ToString() + key_list[20][3].ToString();
            second_round_key_5[2, 0] = key_list[20][4].ToString() + key_list[20][5].ToString();
            second_round_key_5[3, 0] = key_list[20][6].ToString() + key_list[20][7].ToString();

            second_round_key_5[0, 1] = key_list[21][0].ToString() + key_list[21][1].ToString();
            second_round_key_5[1, 1] = key_list[21][2].ToString() + key_list[21][3].ToString();
            second_round_key_5[2, 1] = key_list[21][4].ToString() + key_list[21][5].ToString();
            second_round_key_5[3, 1] = key_list[21][6].ToString() + key_list[21][7].ToString();

            second_round_key_5[0, 2] = key_list[22][0].ToString() + key_list[22][1].ToString();
            second_round_key_5[1, 2] = key_list[22][2].ToString() + key_list[22][3].ToString();
            second_round_key_5[2, 2] = key_list[22][4].ToString() + key_list[22][5].ToString();
            second_round_key_5[3, 2] = key_list[22][6].ToString() + key_list[22][7].ToString();

            second_round_key_5[0, 3] = key_list[23][0].ToString() + key_list[23][1].ToString();
            second_round_key_5[1, 3] = key_list[23][2].ToString() + key_list[23][3].ToString();
            second_round_key_5[2, 3] = key_list[23][4].ToString() + key_list[23][5].ToString();
            second_round_key_5[3, 3] = key_list[23][6].ToString() + key_list[23][7].ToString();
            string[,] add_round_key_5 = AddRoundKey(inverse_sub_bytes_5, second_round_key_5);
            byte[,] inverse_mix_columns_5 = InverseMixColumns(ConvertHexStringsToBytes(add_round_key_5));
            //////////////////////////////////////////////////////////////////////////////////////////////////////
            byte[,] inverse_shift_row_6 = shiftRowsInverse(inverse_mix_columns_5);
            string[,] inverse_sub_bytes_6 = InverseSubytes(ConvertBytesToHexStrings(inverse_shift_row_6));
            string[,] second_round_key_6 = new string[4, 4];
            second_round_key_6[0, 0] = key_list[16][0].ToString() + key_list[16][1].ToString();
            second_round_key_6[1, 0] = key_list[16][2].ToString() + key_list[16][3].ToString();
            second_round_key_6[2, 0] = key_list[16][4].ToString() + key_list[16][5].ToString();
            second_round_key_6[3, 0] = key_list[16][6].ToString() + key_list[16][7].ToString();

            second_round_key_6[0, 1] = key_list[17][0].ToString() + key_list[17][1].ToString();
            second_round_key_6[1, 1] = key_list[17][2].ToString() + key_list[17][3].ToString();
            second_round_key_6[2, 1] = key_list[17][4].ToString() + key_list[17][5].ToString();
            second_round_key_6[3, 1] = key_list[17][6].ToString() + key_list[17][7].ToString();

            second_round_key_6[0, 2] = key_list[18][0].ToString() + key_list[18][1].ToString();
            second_round_key_6[1, 2] = key_list[18][2].ToString() + key_list[18][3].ToString();
            second_round_key_6[2, 2] = key_list[18][4].ToString() + key_list[18][5].ToString();
            second_round_key_6[3, 2] = key_list[18][6].ToString() + key_list[18][7].ToString();

            second_round_key_6[0, 3] = key_list[19][0].ToString() + key_list[19][1].ToString();
            second_round_key_6[1, 3] = key_list[19][2].ToString() + key_list[19][3].ToString();
            second_round_key_6[2, 3] = key_list[19][4].ToString() + key_list[19][5].ToString();
            second_round_key_6[3, 3] = key_list[19][6].ToString() + key_list[19][7].ToString();
            string[,] add_round_key_6 = AddRoundKey(inverse_sub_bytes_6, second_round_key_6);
            byte[,] inverse_mix_columns_6 = InverseMixColumns(ConvertHexStringsToBytes(add_round_key_6));
            ///////////////////////////////////////////////////////////////////////////////////////////////////
            byte[,] inverse_shift_row_7 = shiftRowsInverse(inverse_mix_columns_6);
            string[,] inverse_sub_bytes_7 = InverseSubytes(ConvertBytesToHexStrings(inverse_shift_row_7));
            string[,] second_round_key_7 = new string[4, 4];
            second_round_key_7[0, 0] = key_list[12][0].ToString() + key_list[12][1].ToString();
            second_round_key_7[1, 0] = key_list[12][2].ToString() + key_list[12][3].ToString();
            second_round_key_7[2, 0] = key_list[12][4].ToString() + key_list[12][5].ToString();
            second_round_key_7[3, 0] = key_list[12][6].ToString() + key_list[12][7].ToString();

            second_round_key_7[0, 1] = key_list[13][0].ToString() + key_list[13][1].ToString();
            second_round_key_7[1, 1] = key_list[13][2].ToString() + key_list[13][3].ToString();
            second_round_key_7[2, 1] = key_list[13][4].ToString() + key_list[13][5].ToString();
            second_round_key_7[3, 1] = key_list[13][6].ToString() + key_list[13][7].ToString();

            second_round_key_7[0, 2] = key_list[14][0].ToString() + key_list[14][1].ToString();
            second_round_key_7[1, 2] = key_list[14][2].ToString() + key_list[14][3].ToString();
            second_round_key_7[2, 2] = key_list[14][4].ToString() + key_list[14][5].ToString();
            second_round_key_7[3, 2] = key_list[14][6].ToString() + key_list[14][7].ToString();

            second_round_key_7[0, 3] = key_list[15][0].ToString() + key_list[15][1].ToString();
            second_round_key_7[1, 3] = key_list[15][2].ToString() + key_list[15][3].ToString();
            second_round_key_7[2, 3] = key_list[15][4].ToString() + key_list[15][5].ToString();
            second_round_key_7[3, 3] = key_list[15][6].ToString() + key_list[15][7].ToString();
            string[,] add_round_key_7 = AddRoundKey(inverse_sub_bytes_7, second_round_key_7);
            byte[,] inverse_mix_columns_7 = InverseMixColumns(ConvertHexStringsToBytes(add_round_key_7));
            //////////////////////////////////////////////////////////////////////////////////////////////////
            byte[,] inverse_shift_row_8 = shiftRowsInverse(inverse_mix_columns_7);
            string[,] inverse_sub_bytes_8 = InverseSubytes(ConvertBytesToHexStrings(inverse_shift_row_8));
            string[,] second_round_key_8 = new string[4, 4];
            second_round_key_8[0, 0] = key_list[8][0].ToString() + key_list[8][1].ToString();
            second_round_key_8[1, 0] = key_list[8][2].ToString() + key_list[8][3].ToString();
            second_round_key_8[2, 0] = key_list[8][4].ToString() + key_list[8][5].ToString();
            second_round_key_8[3, 0] = key_list[8][6].ToString() + key_list[8][7].ToString();

            second_round_key_8[0, 1] = key_list[9][0].ToString() + key_list[9][1].ToString();
            second_round_key_8[1, 1] = key_list[9][2].ToString() + key_list[9][3].ToString();
            second_round_key_8[2, 1] = key_list[9][4].ToString() + key_list[9][5].ToString();
            second_round_key_8[3, 1] = key_list[9][6].ToString() + key_list[9][7].ToString();

            second_round_key_8[0, 2] = key_list[10][0].ToString() + key_list[10][1].ToString();
            second_round_key_8[1, 2] = key_list[10][2].ToString() + key_list[10][3].ToString();
            second_round_key_8[2, 2] = key_list[10][4].ToString() + key_list[10][5].ToString();
            second_round_key_8[3, 2] = key_list[10][6].ToString() + key_list[10][7].ToString();

            second_round_key_8[0, 3] = key_list[11][0].ToString() + key_list[11][1].ToString();
            second_round_key_8[1, 3] = key_list[11][2].ToString() + key_list[11][3].ToString();
            second_round_key_8[2, 3] = key_list[11][4].ToString() + key_list[11][5].ToString();
            second_round_key_8[3, 3] = key_list[11][6].ToString() + key_list[11][7].ToString();
            string[,] add_round_key_8 = AddRoundKey(inverse_sub_bytes_8, second_round_key_8);
            byte[,] inverse_mix_columns_8 = InverseMixColumns(ConvertHexStringsToBytes(add_round_key_8));
            ////////////////////////////////////////////////////////////////////////////////////////////////////////////
            byte[,] inverse_shift_row_9 = shiftRowsInverse(inverse_mix_columns_8);
            string[,] inverse_sub_bytes_9 = InverseSubytes(ConvertBytesToHexStrings(inverse_shift_row_9));
            string[,] second_round_key_9 = new string[4, 4];
            second_round_key_9[0, 0] = key_list[4][0].ToString() + key_list[4][1].ToString();
            second_round_key_9[1, 0] = key_list[4][2].ToString() + key_list[4][3].ToString();
            second_round_key_9[2, 0] = key_list[4][4].ToString() + key_list[4][5].ToString();
            second_round_key_9[3, 0] = key_list[4][6].ToString() + key_list[4][7].ToString();

            second_round_key_9[0, 1] = key_list[5][0].ToString() + key_list[5][1].ToString();
            second_round_key_9[1, 1] = key_list[5][2].ToString() + key_list[5][3].ToString();
            second_round_key_9[2, 1] = key_list[5][4].ToString() + key_list[5][5].ToString();
            second_round_key_9[3, 1] = key_list[5][6].ToString() + key_list[5][7].ToString();

            second_round_key_9[0, 2] = key_list[6][0].ToString() + key_list[6][1].ToString();
            second_round_key_9[1, 2] = key_list[6][2].ToString() + key_list[6][3].ToString();
            second_round_key_9[2, 2] = key_list[6][4].ToString() + key_list[6][5].ToString();
            second_round_key_9[3, 2] = key_list[6][6].ToString() + key_list[6][7].ToString();

            second_round_key_9[0, 3] = key_list[7][0].ToString() + key_list[7][1].ToString();
            second_round_key_9[1, 3] = key_list[7][2].ToString() + key_list[7][3].ToString();
            second_round_key_9[2, 3] = key_list[7][4].ToString() + key_list[7][5].ToString();
            second_round_key_9[3, 3] = key_list[7][6].ToString() + key_list[7][7].ToString();
            string[,] add_round_key_9 = AddRoundKey(inverse_sub_bytes_9, second_round_key_9);
            byte[,] inverse_mix_columns_9 = InverseMixColumns(ConvertHexStringsToBytes(add_round_key_9));
            ////////////////////////////////////////////////////////////////////////////////////////////////////
            byte[,] inverse_shift_row_10 = shiftRowsInverse(inverse_mix_columns_9);
            string[,] inverse_sub_bytes_10 = InverseSubytes(ConvertBytesToHexStrings(inverse_shift_row_10));
            string[,] second_round_key_10 = new string[4, 4];
            second_round_key_10[0, 0] = key_list[0][0].ToString() + key_list[0][1].ToString();
            second_round_key_10[1, 0] = key_list[0][2].ToString() + key_list[0][3].ToString();
            second_round_key_10[2, 0] = key_list[0][4].ToString() + key_list[0][5].ToString();
            second_round_key_10[3, 0] = key_list[0][6].ToString() + key_list[0][7].ToString();

            second_round_key_10[0, 1] = key_list[1][0].ToString() + key_list[1][1].ToString();
            second_round_key_10[1, 1] = key_list[1][2].ToString() + key_list[1][3].ToString();
            second_round_key_10[2, 1] = key_list[1][4].ToString() + key_list[1][5].ToString();
            second_round_key_10[3, 1] = key_list[1][6].ToString() + key_list[1][7].ToString();

            second_round_key_10[0, 2] = key_list[2][0].ToString() + key_list[2][1].ToString();
            second_round_key_10[1, 2] = key_list[2][2].ToString() + key_list[2][3].ToString();
            second_round_key_10[2, 2] = key_list[2][4].ToString() + key_list[2][5].ToString();
            second_round_key_10[3, 2] = key_list[2][6].ToString() + key_list[2][7].ToString();

            second_round_key_10[0, 3] = key_list[3][0].ToString() + key_list[3][1].ToString();
            second_round_key_10[1, 3] = key_list[3][2].ToString() + key_list[3][3].ToString();
            second_round_key_10[2, 3] = key_list[3][4].ToString() + key_list[3][5].ToString();
            second_round_key_10[3, 3] = key_list[3][6].ToString() + key_list[3][7].ToString();
            string[,] add_round_key_10 = AddRoundKey(inverse_sub_bytes_10, second_round_key_10);
            string result = "0x";
            result += add_round_key_10[0, 0];
            result += add_round_key_10[1, 0];
            result += add_round_key_10[2, 0];
            result += add_round_key_10[3, 0];

            result += add_round_key_10[0, 1];
            result += add_round_key_10[1, 1];
            result += add_round_key_10[2, 1];
            result += add_round_key_10[3, 1];

            result += add_round_key_10[0, 2];
            result += add_round_key_10[1, 2];
            result += add_round_key_10[2, 2];
            result += add_round_key_10[3, 2];

            result += add_round_key_10[0, 3];
            result += add_round_key_10[1, 3];
            result += add_round_key_10[2, 3];
            result += add_round_key_10[3, 3];

            return result;
            //throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            
            string[,] plainText_matrix = new string[4,4];
            int current_row = 0, current_column = 0;
            int plainText_length = plainText.Length;
            for (int i = 2; i < plainText_length; i+=2)
            {
                if (4 == current_row)
                {
                    current_row = 0;
                    current_column++;
                    plainText_matrix[current_row, current_column] = plainText[i].ToString() + plainText[i + 1].ToString();
                    current_row++;
                }
                else
                {
                    plainText_matrix[current_row, current_column] = plainText[i].ToString() + plainText[i+1].ToString();
                    current_row++;
                }
            }

            string[,] key_matrix = new string[4,4];
            current_row = 0; current_column = 0;
            int key_length = key.Length;
            for (int i = 2; i < key_length; i += 2)
            {
                if (4 == current_row)
                {
                    current_row = 0;
                    current_column++;
                    key_matrix[current_row, current_column] = key[i].ToString() + key[i + 1].ToString();
                    current_row++;
                }
                else
                {
                    key_matrix[current_row, current_column] = key[i].ToString() + key[i + 1].ToString();
                    current_row++;
                }
            }
            List<string> key_list = key_schedule(key_matrix);

            string [,] after_initial_round_key = AddRoundKey(plainText_matrix, key_matrix);
            //////////////////////////////////////////////////////////////////////////////////////////
            string [,] sub_bytes = subytes(after_initial_round_key);
            byte[,] shift_row = shiftRows(ConvertHexStringsToBytes(sub_bytes));
            byte[,] mix_columns = mixColumns(shift_row);
            string[,] first_round_key = new string[4,4];
            first_round_key[0, 0] = key_list[4][0].ToString() + key_list[4][1].ToString();
            first_round_key[1, 0] = key_list[4][2].ToString() + key_list[4][3].ToString();
            first_round_key[2, 0] = key_list[4][4].ToString() + key_list[4][5].ToString();
            first_round_key[3, 0] = key_list[4][6].ToString() + key_list[4][7].ToString();

            first_round_key[0, 1] = key_list[5][0].ToString() + key_list[5][1].ToString();
            first_round_key[1, 1] = key_list[5][2].ToString() + key_list[5][3].ToString();
            first_round_key[2, 1] = key_list[5][4].ToString() + key_list[5][5].ToString();
            first_round_key[3, 1] = key_list[5][6].ToString() + key_list[5][7].ToString();

            first_round_key[0, 2] = key_list[6][0].ToString() + key_list[6][1].ToString();
            first_round_key[1, 2] = key_list[6][2].ToString() + key_list[6][3].ToString();
            first_round_key[2, 2] = key_list[6][4].ToString() + key_list[6][5].ToString();
            first_round_key[3, 2] = key_list[6][6].ToString() + key_list[6][7].ToString();

            first_round_key[0, 3] = key_list[7][0].ToString() + key_list[7][1].ToString();
            first_round_key[1, 3] = key_list[7][2].ToString() + key_list[7][3].ToString();
            first_round_key[2, 3] = key_list[7][4].ToString() + key_list[7][5].ToString();
            first_round_key[3, 3] = key_list[7][6].ToString() + key_list[7][7].ToString();

            string[,] add_round_key = AddRoundKey(ConvertBytesToHexStrings(mix_columns), first_round_key);
            ////////////////////////////////////////////////////////////////////////////////////////////////

            string[,] sub_bytes_2 = subytes(add_round_key);
            byte[,] shift_row_2 = shiftRows(ConvertHexStringsToBytes(sub_bytes_2));
            byte[,] mix_columns_2 = mixColumns(shift_row_2);
            string[,] first_round_key_2 = new string[4, 4];
            first_round_key_2[0, 0] = key_list[8][0].ToString() + key_list[8][1].ToString();
            first_round_key_2[1, 0] = key_list[8][2].ToString() + key_list[8][3].ToString();
            first_round_key_2[2, 0] = key_list[8][4].ToString() + key_list[8][5].ToString();
            first_round_key_2[3, 0] = key_list[8][6].ToString() + key_list[8][7].ToString();

            first_round_key_2[0, 1] = key_list[9][0].ToString() + key_list[9][1].ToString();
            first_round_key_2[1, 1] = key_list[9][2].ToString() + key_list[9][3].ToString();
            first_round_key_2[2, 1] = key_list[9][4].ToString() + key_list[9][5].ToString();
            first_round_key_2[3, 1] = key_list[9][6].ToString() + key_list[9][7].ToString();

            first_round_key_2[0, 2] = key_list[10][0].ToString() + key_list[10][1].ToString();
            first_round_key_2[1, 2] = key_list[10][2].ToString() + key_list[10][3].ToString();
            first_round_key_2[2, 2] = key_list[10][4].ToString() + key_list[10][5].ToString();
            first_round_key_2[3, 2] = key_list[10][6].ToString() + key_list[10][7].ToString();

            first_round_key_2[0, 3] = key_list[11][0].ToString() + key_list[11][1].ToString();
            first_round_key_2[1, 3] = key_list[11][2].ToString() + key_list[11][3].ToString();
            first_round_key_2[2, 3] = key_list[11][4].ToString() + key_list[11][5].ToString();
            first_round_key_2[3, 3] = key_list[11][6].ToString() + key_list[11][7].ToString();

            string[,] add_round_key_2 = AddRoundKey(ConvertBytesToHexStrings(mix_columns_2), first_round_key_2);
            ////////////////////////////////////////////////////////////////////////////////////////////////
            string[,] sub_bytes_3 = subytes(add_round_key_2);
            byte[,] shift_row_3 = shiftRows(ConvertHexStringsToBytes(sub_bytes_3));
            byte[,] mix_columns_3 = mixColumns(shift_row_3);
            string[,] first_round_key_3 = new string[4, 4];
            first_round_key_3[0, 0] = key_list[12][0].ToString() + key_list[12][1].ToString();
            first_round_key_3[1, 0] = key_list[12][2].ToString() + key_list[12][3].ToString();
            first_round_key_3[2, 0] = key_list[12][4].ToString() + key_list[12][5].ToString();
            first_round_key_3[3, 0] = key_list[12][6].ToString() + key_list[12][7].ToString();

            first_round_key_3[0, 1] = key_list[13][0].ToString() + key_list[13][1].ToString();
            first_round_key_3[1, 1] = key_list[13][2].ToString() + key_list[13][3].ToString();
            first_round_key_3[2, 1] = key_list[13][4].ToString() + key_list[13][5].ToString();
            first_round_key_3[3, 1] = key_list[13][6].ToString() + key_list[13][7].ToString();

            first_round_key_3[0, 2] = key_list[14][0].ToString() + key_list[14][1].ToString();
            first_round_key_3[1, 2] = key_list[14][2].ToString() + key_list[14][3].ToString();
            first_round_key_3[2, 2] = key_list[14][4].ToString() + key_list[14][5].ToString();
            first_round_key_3[3, 2] = key_list[14][6].ToString() + key_list[14][7].ToString();

            first_round_key_3[0, 3] = key_list[15][0].ToString() + key_list[15][1].ToString();
            first_round_key_3[1, 3] = key_list[15][2].ToString() + key_list[15][3].ToString();
            first_round_key_3[2, 3] = key_list[15][4].ToString() + key_list[15][5].ToString();
            first_round_key_3[3, 3] = key_list[15][6].ToString() + key_list[15][7].ToString();

            string[,] add_round_key_3 = AddRoundKey(ConvertBytesToHexStrings(mix_columns_3), first_round_key_3);
            ////////////////////////////////////////////////////////////////////////////////////////////////////
            string[,] sub_bytes_4 = subytes(add_round_key_3);
            byte[,] shift_row_4 = shiftRows(ConvertHexStringsToBytes(sub_bytes_4));
            byte[,] mix_columns_4 = mixColumns(shift_row_4);
            string[,] first_round_key_4 = new string[4, 4];
            first_round_key_4[0, 0] = key_list[16][0].ToString() + key_list[16][1].ToString();
            first_round_key_4[1, 0] = key_list[16][2].ToString() + key_list[16][3].ToString();
            first_round_key_4[2, 0] = key_list[16][4].ToString() + key_list[16][5].ToString();
            first_round_key_4[3, 0] = key_list[16][6].ToString() + key_list[16][7].ToString();

            first_round_key_4[0, 1] = key_list[17][0].ToString() + key_list[17][1].ToString();
            first_round_key_4[1, 1] = key_list[17][2].ToString() + key_list[17][3].ToString();
            first_round_key_4[2, 1] = key_list[17][4].ToString() + key_list[17][5].ToString();
            first_round_key_4[3, 1] = key_list[17][6].ToString() + key_list[17][7].ToString();

            first_round_key_4[0, 2] = key_list[18][0].ToString() + key_list[18][1].ToString();
            first_round_key_4[1, 2] = key_list[18][2].ToString() + key_list[18][3].ToString();
            first_round_key_4[2, 2] = key_list[18][4].ToString() + key_list[18][5].ToString();
            first_round_key_4[3, 2] = key_list[18][6].ToString() + key_list[18][7].ToString();

            first_round_key_4[0, 3] = key_list[19][0].ToString() + key_list[19][1].ToString();
            first_round_key_4[1, 3] = key_list[19][2].ToString() + key_list[19][3].ToString();
            first_round_key_4[2, 3] = key_list[19][4].ToString() + key_list[19][5].ToString();
            first_round_key_4[3, 3] = key_list[19][6].ToString() + key_list[19][7].ToString();

            string[,] add_round_key_4 = AddRoundKey(ConvertBytesToHexStrings(mix_columns_4), first_round_key_4);
            //////////////////////////////////////////////////////////////////////////////////////////////////////
            string[,] sub_bytes_5 = subytes(add_round_key_4);
            byte[,] shift_row_5 = shiftRows(ConvertHexStringsToBytes(sub_bytes_5));
            byte[,] mix_columns_5 = mixColumns(shift_row_5);
            string[,] first_round_key_5 = new string[4, 4];
            first_round_key_5[0, 0] = key_list[20][0].ToString() + key_list[20][1].ToString();
            first_round_key_5[1, 0] = key_list[20][2].ToString() + key_list[20][3].ToString();
            first_round_key_5[2, 0] = key_list[20][4].ToString() + key_list[20][5].ToString();
            first_round_key_5[3, 0] = key_list[20][6].ToString() + key_list[20][7].ToString();

            first_round_key_5[0, 1] = key_list[21][0].ToString() + key_list[21][1].ToString();
            first_round_key_5[1, 1] = key_list[21][2].ToString() + key_list[21][3].ToString();
            first_round_key_5[2, 1] = key_list[21][4].ToString() + key_list[21][5].ToString();
            first_round_key_5[3, 1] = key_list[21][6].ToString() + key_list[21][7].ToString();

            first_round_key_5[0, 2] = key_list[22][0].ToString() + key_list[22][1].ToString();
            first_round_key_5[1, 2] = key_list[22][2].ToString() + key_list[22][3].ToString();
            first_round_key_5[2, 2] = key_list[22][4].ToString() + key_list[22][5].ToString();
            first_round_key_5[3, 2] = key_list[22][6].ToString() + key_list[22][7].ToString();

            first_round_key_5[0, 3] = key_list[23][0].ToString() + key_list[23][1].ToString();
            first_round_key_5[1, 3] = key_list[23][2].ToString() + key_list[23][3].ToString();
            first_round_key_5[2, 3] = key_list[23][4].ToString() + key_list[23][5].ToString();
            first_round_key_5[3, 3] = key_list[23][6].ToString() + key_list[23][7].ToString();

            string[,] add_round_key_5 = AddRoundKey(ConvertBytesToHexStrings(mix_columns_5), first_round_key_5);
            ///////////////////////////////////////////////////////////////////////////////////////////////////
            string[,] sub_bytes_6 = subytes(add_round_key_5);
            byte[,] shift_row_6 = shiftRows(ConvertHexStringsToBytes(sub_bytes_6));
            byte[,] mix_columns_6 = mixColumns(shift_row_6);
            string[,] first_round_key_6 = new string[4, 4];
            first_round_key_6[0, 0] = key_list[24][0].ToString() + key_list[24][1].ToString();
            first_round_key_6[1, 0] = key_list[24][2].ToString() + key_list[24][3].ToString();
            first_round_key_6[2, 0] = key_list[24][4].ToString() + key_list[24][5].ToString();
            first_round_key_6[3, 0] = key_list[24][6].ToString() + key_list[24][7].ToString();

            first_round_key_6[0, 1] = key_list[25][0].ToString() + key_list[25][1].ToString();
            first_round_key_6[1, 1] = key_list[25][2].ToString() + key_list[25][3].ToString();
            first_round_key_6[2, 1] = key_list[25][4].ToString() + key_list[25][5].ToString();
            first_round_key_6[3, 1] = key_list[25][6].ToString() + key_list[25][7].ToString();

            first_round_key_6[0, 2] = key_list[26][0].ToString() + key_list[26][1].ToString();
            first_round_key_6[1, 2] = key_list[26][2].ToString() + key_list[26][3].ToString();
            first_round_key_6[2, 2] = key_list[26][4].ToString() + key_list[26][5].ToString();
            first_round_key_6[3, 2] = key_list[26][6].ToString() + key_list[26][7].ToString();

            first_round_key_6[0, 3] = key_list[27][0].ToString() + key_list[27][1].ToString();
            first_round_key_6[1, 3] = key_list[27][2].ToString() + key_list[27][3].ToString();
            first_round_key_6[2, 3] = key_list[27][4].ToString() + key_list[27][5].ToString();
            first_round_key_6[3, 3] = key_list[27][6].ToString() + key_list[27][7].ToString();

            string[,] add_round_key_6 = AddRoundKey(ConvertBytesToHexStrings(mix_columns_6), first_round_key_6);
            ////////////////////////////////////////////////////////////////////////////////////////////////////
            string[,] sub_bytes_7 = subytes(add_round_key_6);
            byte[,] shift_row_7 = shiftRows(ConvertHexStringsToBytes(sub_bytes_7));
            byte[,] mix_columns_7 = mixColumns(shift_row_7);
            string[,] first_round_key_7 = new string[4, 4];
            first_round_key_7[0, 0] = key_list[28][0].ToString() + key_list[28][1].ToString();
            first_round_key_7[1, 0] = key_list[28][2].ToString() + key_list[28][3].ToString();
            first_round_key_7[2, 0] = key_list[28][4].ToString() + key_list[28][5].ToString();
            first_round_key_7[3, 0] = key_list[28][6].ToString() + key_list[28][7].ToString();

            first_round_key_7[0, 1] = key_list[29][0].ToString() + key_list[29][1].ToString();
            first_round_key_7[1, 1] = key_list[29][2].ToString() + key_list[29][3].ToString();
            first_round_key_7[2, 1] = key_list[29][4].ToString() + key_list[29][5].ToString();
            first_round_key_7[3, 1] = key_list[29][6].ToString() + key_list[29][7].ToString();

            first_round_key_7[0, 2] = key_list[30][0].ToString() + key_list[30][1].ToString();
            first_round_key_7[1, 2] = key_list[30][2].ToString() + key_list[30][3].ToString();
            first_round_key_7[2, 2] = key_list[30][4].ToString() + key_list[30][5].ToString();
            first_round_key_7[3, 2] = key_list[30][6].ToString() + key_list[30][7].ToString();

            first_round_key_7[0, 3] = key_list[31][0].ToString() + key_list[31][1].ToString();
            first_round_key_7[1, 3] = key_list[31][2].ToString() + key_list[31][3].ToString();
            first_round_key_7[2, 3] = key_list[31][4].ToString() + key_list[31][5].ToString();
            first_round_key_7[3, 3] = key_list[31][6].ToString() + key_list[31][7].ToString();

            string[,] add_round_key_7 = AddRoundKey(ConvertBytesToHexStrings(mix_columns_7), first_round_key_7);
            /////////////////////////////////////////////////////////////////////////////////////////////////////
            string[,] sub_bytes_8 = subytes(add_round_key_7);
            byte[,] shift_row_8 = shiftRows(ConvertHexStringsToBytes(sub_bytes_8));
            byte[,] mix_columns_8 = mixColumns(shift_row_8);
            string[,] first_round_key_8 = new string[4, 4];
            first_round_key_8[0, 0] = key_list[32][0].ToString() + key_list[32][1].ToString();
            first_round_key_8[1, 0] = key_list[32][2].ToString() + key_list[32][3].ToString();
            first_round_key_8[2, 0] = key_list[32][4].ToString() + key_list[32][5].ToString();
            first_round_key_8[3, 0] = key_list[32][6].ToString() + key_list[32][7].ToString();

            first_round_key_8[0, 1] = key_list[33][0].ToString() + key_list[33][1].ToString();
            first_round_key_8[1, 1] = key_list[33][2].ToString() + key_list[33][3].ToString();
            first_round_key_8[2, 1] = key_list[33][4].ToString() + key_list[33][5].ToString();
            first_round_key_8[3, 1] = key_list[33][6].ToString() + key_list[33][7].ToString();

            first_round_key_8[0, 2] = key_list[34][0].ToString() + key_list[34][1].ToString();
            first_round_key_8[1, 2] = key_list[34][2].ToString() + key_list[34][3].ToString();
            first_round_key_8[2, 2] = key_list[34][4].ToString() + key_list[34][5].ToString();
            first_round_key_8[3, 2] = key_list[34][6].ToString() + key_list[34][7].ToString();

            first_round_key_8[0, 3] = key_list[35][0].ToString() + key_list[35][1].ToString();
            first_round_key_8[1, 3] = key_list[35][2].ToString() + key_list[35][3].ToString();
            first_round_key_8[2, 3] = key_list[35][4].ToString() + key_list[35][5].ToString();
            first_round_key_8[3, 3] = key_list[35][6].ToString() + key_list[35][7].ToString();

            string[,] add_round_key_8 = AddRoundKey(ConvertBytesToHexStrings(mix_columns_8), first_round_key_8);
            ////////////////////////////////////////////////////////////////////////////////////////////////////////
            string[,] sub_bytes_9 = subytes(add_round_key_8);
            byte[,] shift_row_9 = shiftRows(ConvertHexStringsToBytes(sub_bytes_9));
            byte[,] mix_columns_9 = mixColumns(shift_row_9);
            string[,] first_round_key_9 = new string[4, 4];
            first_round_key_9[0, 0] = key_list[36][0].ToString() + key_list[36][1].ToString();
            first_round_key_9[1, 0] = key_list[36][2].ToString() + key_list[36][3].ToString();
            first_round_key_9[2, 0] = key_list[36][4].ToString() + key_list[36][5].ToString();
            first_round_key_9[3, 0] = key_list[36][6].ToString() + key_list[36][7].ToString();

            first_round_key_9[0, 1] = key_list[37][0].ToString() + key_list[37][1].ToString();
            first_round_key_9[1, 1] = key_list[37][2].ToString() + key_list[37][3].ToString();
            first_round_key_9[2, 1] = key_list[37][4].ToString() + key_list[37][5].ToString();
            first_round_key_9[3, 1] = key_list[37][6].ToString() + key_list[37][7].ToString();

            first_round_key_9[0, 2] = key_list[38][0].ToString() + key_list[38][1].ToString();
            first_round_key_9[1, 2] = key_list[38][2].ToString() + key_list[38][3].ToString();
            first_round_key_9[2, 2] = key_list[38][4].ToString() + key_list[38][5].ToString();
            first_round_key_9[3, 2] = key_list[38][6].ToString() + key_list[38][7].ToString();

            first_round_key_9[0, 3] = key_list[39][0].ToString() + key_list[39][1].ToString();
            first_round_key_9[1, 3] = key_list[39][2].ToString() + key_list[39][3].ToString();
            first_round_key_9[2, 3] = key_list[39][4].ToString() + key_list[39][5].ToString();
            first_round_key_9[3, 3] = key_list[39][6].ToString() + key_list[39][7].ToString();

            string[,] add_round_key_9 = AddRoundKey(ConvertBytesToHexStrings(mix_columns_9), first_round_key_9);
            ////////////////////////////////////////////////////////////////////////////////////////////////////
            string[,] sub_bytes_10 = subytes(add_round_key_9);
            byte[,] shift_row_10 = shiftRows(ConvertHexStringsToBytes(sub_bytes_10));
            //byte[,] mix_columns_10 = mixColumns(shift_row_10);
            string[,] first_round_key_10 = new string[4, 4];
            first_round_key_10[0, 0] = key_list[40][0].ToString() + key_list[40][1].ToString();
            first_round_key_10[1, 0] = key_list[40][2].ToString() + key_list[40][3].ToString();
            first_round_key_10[2, 0] = key_list[40][4].ToString() + key_list[40][5].ToString();
            first_round_key_10[3, 0] = key_list[40][6].ToString() + key_list[40][7].ToString();

            first_round_key_10[0, 1] = key_list[41][0].ToString() + key_list[41][1].ToString();
            first_round_key_10[1, 1] = key_list[41][2].ToString() + key_list[41][3].ToString();
            first_round_key_10[2, 1] = key_list[41][4].ToString() + key_list[41][5].ToString();
            first_round_key_10[3, 1] = key_list[41][6].ToString() + key_list[41][7].ToString();

            first_round_key_10[0, 2] = key_list[42][0].ToString() + key_list[42][1].ToString();
            first_round_key_10[1, 2] = key_list[42][2].ToString() + key_list[42][3].ToString();
            first_round_key_10[2, 2] = key_list[42][4].ToString() + key_list[42][5].ToString();
            first_round_key_10[3, 2] = key_list[42][6].ToString() + key_list[42][7].ToString();

            first_round_key_10[0, 3] = key_list[43][0].ToString() + key_list[43][1].ToString();
            first_round_key_10[1, 3] = key_list[43][2].ToString() + key_list[43][3].ToString();
            first_round_key_10[2, 3] = key_list[43][4].ToString() + key_list[43][5].ToString();
            first_round_key_10[3, 3] = key_list[43][6].ToString() + key_list[43][7].ToString();

            string[,] add_round_key_10 = AddRoundKey(ConvertBytesToHexStrings(shift_row_10), first_round_key_10);
            string result = "0x";
            result += add_round_key_10[0,0];
            result += add_round_key_10[1,0];
            result += add_round_key_10[2,0];
            result += add_round_key_10[3,0];

            result += add_round_key_10[0,1];
            result += add_round_key_10[1,1];
            result += add_round_key_10[2,1];
            result += add_round_key_10[3,1];

            result += add_round_key_10[0,2];
            result += add_round_key_10[1,2];
            result += add_round_key_10[2,2];
            result += add_round_key_10[3,2];

            result += add_round_key_10[0,3];
            result += add_round_key_10[1,3];
            result += add_round_key_10[2,3];
            result += add_round_key_10[3,3];

            return result;


            //throw new NotImplementedException();
        }
    }
}
