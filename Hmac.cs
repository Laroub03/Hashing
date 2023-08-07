using System;
using System.Security.Cryptography;
using System.Text;

namespace CryptographyInDotNet
{
    public interface IHmacAlgorithm
    {
        byte[] ComputeHmac(byte[] toBeHashed, byte[] key);
    }

    public class HmacSHA256Algorithm : IHmacAlgorithm
    {
        public byte[] ComputeHmac(byte[] toBeHashed, byte[] key)
        {
            using var hmac = new HMACSHA256(key);
            return hmac.ComputeHash(toBeHashed);
        }
    }

    public class HmacSHA1Algorithm : IHmacAlgorithm
    {
        public byte[] ComputeHmac(byte[] toBeHashed, byte[] key)
        {
            using var hmac = new HMACSHA1(key);
            return hmac.ComputeHash(toBeHashed);
        }
    }

    public class HmacSHA512Algorithm : IHmacAlgorithm
    {
        public byte[] ComputeHmac(byte[] toBeHashed, byte[] key)
        {
            using var hmac = new HMACSHA512(key);
            return hmac.ComputeHash(toBeHashed);
        }
    }

    public class HmacMD5Algorithm : IHmacAlgorithm
    {
        public byte[] ComputeHmac(byte[] toBeHashed, byte[] key)
        {
            using var hmac = new HMACMD5(key);
            return hmac.ComputeHash(toBeHashed);
        }
    }

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

        public static byte[] GenerateKey()
        {
            var randomNumberGenerator = RandomNumberGenerator.Create();
            byte[] randomBytes = new byte[32]; // Adjust the size as needed
            randomNumberGenerator.GetBytes(randomBytes);
            return randomBytes;
        }
    }
}
