using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Security.Cryptography;

namespace Server
{
    class Program
    {
        #region Methods
        // Check current socket is connected or disconnect
        // Reference source: https://stackoverflow.com/questions/2661764/how-to-check-if-a-socket-is-connected-disconnected-in-c
        private static bool SocketConnected(Socket s)
        {
            bool part1 = s.Poll(1000, SelectMode.SelectRead);
            bool part2 = (s.Available == 0);
            if (part1 && part2)
                return false;
            else
                return true;
        }
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
        #endregion

        /* MAIN */
        private static Socket listener;
        private static IPAddress localAddr = IPAddress.Parse("127.0.0.1");
        private static int port = 8080;
        private static IPEndPoint ipe = new IPEndPoint(localAddr, port);
        private static string data = null;      // Data received

        private static string password = "NT106L22";    // Example password

        static void Main(string[] args)
        {
            Console.WriteLine("---------------------------------");
            Console.WriteLine("------------SERVER---------------");
            Console.WriteLine("---------------------------------");

            try
            {
                listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                listener.Bind(ipe);
                listener.Listen(-1);

                Console.WriteLine("Waiting for a connection");
                Socket client = listener.Accept();
                Console.WriteLine("Connected");

                NetworkStream stream = new NetworkStream(client);
                StreamReader reader = new StreamReader(stream);

                while (SocketConnected(client))
                {
                    data = null;
                    data = reader.ReadLine();

                    if (SocketConnected(client))
                        Console.WriteLine("Received: {0}", data);
                }

                Console.WriteLine("---------------------------------");
                Console.WriteLine($"Raw encrypted data: {data}");

                string decryptedData = Decrypt(data, password);
                string hashCode = CalcHash(decryptedData);
                Console.WriteLine($"Decrypted data: {decryptedData}");
                Console.WriteLine($"Hash code: {hashCode}");

                Console.WriteLine("---------------------------------");
                Console.WriteLine("Disconnected");
                stream.Close();
                client.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Socketexception {0}", ex.Message);
            }
            finally
            {
                listener.Close();
            }

            /* Stop console to show */
            Console.ReadKey();
        }
    }
}
