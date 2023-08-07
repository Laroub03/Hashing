using CryptographyInDotNet;
using System.Security.Cryptography;
using System.Text;
using System;

namespace CryptographyInDotNet
{
    class Program
    {
        static void Main()
        {
            // Define original messages for hashing
            const string originalMessage = "Original Message to hash";
            const string originalMessage2 = "Original Message to hash";

            // Print header
            Console.WriteLine("HMAC Demonstration in .NET");
            Console.WriteLine("--------------------------");
            Console.WriteLine();

            // Generate a random key for HMAC calculation
            var key = HmacCalculator.GenerateKey();

            // Create HMAC calculators with different algorithms
            var hmacCalculatorSHA256 = new HmacCalculator(new HmacSHA256Algorithm());
            var hmacCalculatorSHA1 = new HmacCalculator(new HmacSHA1Algorithm());
            var hmacCalculatorSHA512 = new HmacCalculator(new HmacSHA512Algorithm());
            var hmacCalculatorMD5 = new HmacCalculator(new HmacMD5Algorithm());

            // Calculate HMAC for the original messages using different algorithms and keys
            var hmacSHA256Message = hmacCalculatorSHA256.CalculateHmac(Encoding.UTF8.GetBytes(originalMessage), key);
            var hmacSHA256Message2 = hmacCalculatorSHA256.CalculateHmac(Encoding.UTF8.GetBytes(originalMessage2), key);
            var hmacSHA1Message = hmacCalculatorSHA1.CalculateHmac(Encoding.UTF8.GetBytes(originalMessage), key);
            var hmacSHA1Message2 = hmacCalculatorSHA1.CalculateHmac(Encoding.UTF8.GetBytes(originalMessage2), key);
            var hmacSHA512Message = hmacCalculatorSHA512.CalculateHmac(Encoding.UTF8.GetBytes(originalMessage), key);
            var hmacSHA512Message2 = hmacCalculatorSHA512.CalculateHmac(Encoding.UTF8.GetBytes(originalMessage2), key);
            var hmacMD5Message = hmacCalculatorMD5.CalculateHmac(Encoding.UTF8.GetBytes(originalMessage), key);
            var hmacMD5Message2 = hmacCalculatorMD5.CalculateHmac(Encoding.UTF8.GetBytes(originalMessage2), key);

            // Print HMAC results for each algorithm and message
            Console.WriteLine();
            Console.WriteLine("SHA 256 HMAC");
            Console.WriteLine();
            Console.WriteLine("Message 1 hash = " + Convert.ToBase64String(hmacSHA256Message));
            Console.WriteLine("Message 2 hash = " + Convert.ToBase64String(hmacSHA256Message2));

            Console.WriteLine();
            Console.WriteLine("SHA 1 HMAC");
            Console.WriteLine();
            Console.WriteLine("Message 1 hash = " + Convert.ToBase64String(hmacSHA1Message));
            Console.WriteLine("Message 2 hash = " + Convert.ToBase64String(hmacSHA1Message2));

            Console.WriteLine();
            Console.WriteLine("SHA 512 HMAC");
            Console.WriteLine();
            Console.WriteLine("Message 1 hash = " + Convert.ToBase64String(hmacSHA512Message));
            Console.WriteLine("Message 2 hash = " + Convert.ToBase64String(hmacSHA512Message2));

            Console.WriteLine();
            Console.WriteLine("MD5 HMAC");
            Console.WriteLine();
            Console.WriteLine("Message 1 hash = " + Convert.ToBase64String(hmacMD5Message));
            Console.WriteLine("Message 2 hash = " + Convert.ToBase64String(hmacMD5Message2));

            // Wait for user input before exiting
            Console.ReadLine();
        }
    }
}
