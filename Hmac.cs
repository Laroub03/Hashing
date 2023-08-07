using System;
using System.Security.Cryptography;
using System.Text;

namespace CryptographyInDotNet
{
    // Interface for HMAC algorithm
    public interface IHmacAlgorithm
    {
        byte[] ComputeHmac(byte[] toBeHashed, byte[] key);
    }

    // Implementation of HMAC algorithm using SHA-256
    public class HmacSHA256Algorithm : IHmacAlgorithm
    {
        public byte[] ComputeHmac(byte[] toBeHashed, byte[] key)
        {
            using var hmac = new HMACSHA256(key);
            return hmac.ComputeHash(toBeHashed);
        }
    }

    // Implementation of HMAC algorithm using SHA-1
    public class HmacSHA1Algorithm : IHmacAlgorithm
    {
        public byte[] ComputeHmac(byte[] toBeHashed, byte[] key)
        {
            using var hmac = new HMACSHA1(key);
            return hmac.ComputeHash(toBeHashed);
        }
    }

    // Implementation of HMAC algorithm using SHA-512
    public class HmacSHA512Algorithm : IHmacAlgorithm
    {
        public byte[] ComputeHmac(byte[] toBeHashed, byte[] key)
        {
            using var hmac = new HMACSHA512(key);
            return hmac.ComputeHash(toBeHashed);
        }
    }

    // Implementation of HMAC algorithm using MD5
    public class HmacMD5Algorithm : IHmacAlgorithm
    {
        public byte[] ComputeHmac(byte[] toBeHashed, byte[] key)
        {
            using var hmac = new HMACMD5(key);
            return hmac.ComputeHash(toBeHashed);
        }
    }

    // Class for calculating HMAC using a specified algorithm
    public class HmacCalculator
    {
        private readonly IHmacAlgorithm _algorithm;

        public HmacCalculator(IHmacAlgorithm algorithm)
        {
            _algorithm = algorithm;
        }

        public byte[] CalculateHmac(byte[] toBeHashed, byte[] key)
        {
            return _algorithm.ComputeHmac(toBeHashed, key);
        }

        // Generate a random key for HMAC calculation
        public static byte[] GenerateKey()
        {
            var randomNumberGenerator = RandomNumberGenerator.Create();
            byte[] randomBytes = new byte[32]; // Adjust the size as needed
            randomNumberGenerator.GetBytes(randomBytes);
            return randomBytes;
        }
    }
}
