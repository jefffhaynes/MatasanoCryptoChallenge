using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace MatasanoCryptoChallenge
{
    public class EcbCbcDetectionOracle
    {
        readonly AesCryptoServiceProvider _provider = new AesCryptoServiceProvider();
        readonly Random _random = new Random();

        private void GenerateKey(out byte[] key, out byte[] iv)
        {
            _provider.GenerateKey();
            _provider.GenerateIV();

            key = _provider.Key;
            iv = _provider.IV;
        }

        private IEnumerable<byte> GetPadding()
        {
            int count = (int)Math.Floor(5 * _random.NextDouble()) + 5;
            var padding = new byte[count];
            _random.NextBytes(padding);
            return padding;
        } 

        public byte[] Encrypt(string value, out bool isEcb)
        {
            var data = Encoding.UTF8.GetBytes(value);

            var paddedData = GetPadding().Concat(data).Concat(GetPadding()).ToArray();

            isEcb = _random.NextDouble() > 0.5;

            return isEcb ? EncryptEcb(paddedData) : EncryptCbc(paddedData);
        }

        private byte[] EncryptEcb(byte[] data)
        {
            return Encrypt(data, CipherMode.ECB);
        }

        private byte[] EncryptCbc(byte[] data)
        {
            return Encrypt(data, CipherMode.CBC);
        }

        private byte[] Encrypt(byte[] data, CipherMode mode)
        {
            var aes = new AesManaged
            {
                Mode = mode,
                Padding = PaddingMode.PKCS7
            };

            byte[] key, iv;
            GenerateKey(out key, out iv);

            var transform = aes.CreateEncryptor(key, iv);

            var stream = new MemoryStream();
            using (var cryptoStream = new CryptoStream(stream, transform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(data, 0, data.Length);
                cryptoStream.Flush();
                return stream.ToArray();
            }
        }

        public static bool IsEcb(byte[] cipherText, int blockSize)
        {
            var blocks = cipherText.Partition(blockSize).ToArray();
            var distinctBlocks = blocks.Select(block => block.ToArray()).Distinct(new ByteArrayComparer());
            return blocks.Length != distinctBlocks.Count();
        }
    }
}
