using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Bai1
{
    class Program
    {
        #region Methods
        // Reference source: https://stackoverflow.com/questions/11454004/calculate-a-md5-hash-from-a-string
        private static string CalcHash(string plainText)
        {
            MD5 md5 = new MD5CryptoServiceProvider();
            // Convert the string to byte array to handle
            byte[] bytes = Encoding.ASCII.GetBytes(plainText);
            md5.ComputeHash(bytes);
            byte[] result = md5.Hash;
            // Convert the byte array to hexadecimal string
            StringBuilder stringBuilder = new StringBuilder();
            for (int i = 0; i < result.Length; i++)
            {
                stringBuilder.Append(result[i].ToString("x2"));
            }

            return stringBuilder.ToString();
        }

        // Reference source: https://ngotuongdan.wordpress.com/2015/12/16/c-ma-hoa-va-giai-ma-thong-tin-voi-mat-khau/
        private static string Encrypt(string plainText, string password)
        {
            bool useHashing = true;
            byte[] keyArray;
            byte[] toEncryptArray = UTF8Encoding.UTF8.GetBytes(plainText);

            if (useHashing)
            {
                MD5CryptoServiceProvider hashmd5 = new MD5CryptoServiceProvider();
                keyArray = hashmd5.ComputeHash(UTF8Encoding.UTF8.GetBytes(password));
            }
            else
                keyArray = UTF8Encoding.UTF8.GetBytes(password);

            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            tdes.Key = keyArray;
            tdes.Mode = CipherMode.ECB;
            tdes.Padding = PaddingMode.PKCS7;

            ICryptoTransform cTransform = tdes.CreateEncryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);

            return Convert.ToBase64String(resultArray, 0, resultArray.Length);
        }
        private static string Decrypt(string encryptedText, string password)
        {
            bool useHashing = true;
            byte[] keyArray;
            byte[] toEncryptArray = Convert.FromBase64String(encryptedText);

            if (useHashing)
            {
                MD5CryptoServiceProvider hashmd5 = new MD5CryptoServiceProvider();
                keyArray = hashmd5.ComputeHash(UTF8Encoding.UTF8.GetBytes(password));
            }
            else
                keyArray = UTF8Encoding.UTF8.GetBytes(password);

            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            tdes.Key = keyArray;
            tdes.Mode = CipherMode.ECB;
            tdes.Padding = PaddingMode.PKCS7;

            ICryptoTransform cTransform = tdes.CreateDecryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);

            return UTF8Encoding.UTF8.GetString(resultArray);
        }

        // Reference source: https://www.c-sharpcorner.com/article/how-to-generate-a-random-password-in-c-sharp-and-net-core/
        // Generate a random string with a given size and case. 
        private static string RandomString(int size, bool lowerCase)
        {
            StringBuilder builder = new StringBuilder();
            Random random = new Random();
            char ch;
            for (int i = 0; i < size; i++)
            {
                ch = Convert.ToChar(Convert.ToInt32(Math.Floor(26 * random.NextDouble() + 65)));
                builder.Append(ch);
            }
            if (lowerCase)
                return builder.ToString().ToLower();
            return builder.ToString();
        }

        // Generate a random password of a given length (default: 4)
        private static string RandomPassword(int size = 4)
        {
            StringBuilder builder = new StringBuilder();
            // Generate a random number  
            Random random = new Random();
            int num = random.Next(1000, 9999);

            builder.Append(RandomString(4, true));
            builder.Append(num);
            builder.Append(RandomString(2, false));
            return builder.ToString();
        }
        #endregion

        /* MAIN */
        private static string plainText = null;
        private static string password = null;

        static void Main(string[] args)
        {
            plainText = Console.ReadLine();
            password = RandomPassword(/*optional*/);    // password size default: 4

            string encryptedText = Encrypt(plainText, password);
            string decryptedText = Decrypt(plainText, password);
            string hashCode = CalcHash(plainText);

            Console.WriteLine($"Encrypted text: {encryptedText}");
            Console.WriteLine($"Encrypted text size: {encryptedText.Length}");
            Console.WriteLine($"Decrypted text: {decryptedText}");
            Console.WriteLine($"Encrypted text size: {decryptedText.Length}");
            Console.WriteLine("Hash code: " + hashCode);
            Console.WriteLine($"Hash code size: {hashCode}");

            Console.ReadKey();
        }
    }
}