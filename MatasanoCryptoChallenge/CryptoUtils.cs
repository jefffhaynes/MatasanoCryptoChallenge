using System;
using System.Collections.Generic;
using System.Linq;

namespace MatasanoCryptoChallenge
{
    public static class CryptoUtils
    {
        public static IEnumerable<byte> PadPkcs7(this IEnumerable<byte> value, byte blockSize)
        {
            int count = 0;
            foreach (var b in value)
            {
                yield return b;
                count++;
            }

            var remainder = blockSize % count;

            for (int i = 0; i < remainder; i++)
                yield return (byte)remainder;
        }

        public static IEnumerable<byte> RemovePkcs7(this IEnumerable<byte> value)
        {
            // TODO make this memory efficient

            var data = value.ToArray();

            var paddingLength = data[data.Length - 1];
            var dataLength = data.Length - paddingLength;

            var padding = new byte[paddingLength];
            Array.Copy(data, dataLength, padding, 0, paddingLength);

            if (!padding.All(b => b == paddingLength))
                throw new InvalidOperationException("Invalid padding");

            for (int i = 0; i < dataLength; i++)
                yield return data[i];
        }
    }
}
