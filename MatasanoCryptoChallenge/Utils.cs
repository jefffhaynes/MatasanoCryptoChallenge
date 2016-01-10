using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

namespace MatasanoCryptoChallenge
{
    public static class Utils
    {
        public static byte[] HexToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x%2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

        public static string ByteArrayToHex(byte[] data)
        {
            return string.Concat(Array.ConvertAll(data, x => x.ToString("X2")));
        }

        public static IEnumerable<byte> Xor(IEnumerable<byte> a, IEnumerable<byte> b)
        {
            return a.Zip(b, (b1, b2) => (byte) (b1 ^ b2));
        }

        public static IEnumerable<byte> Xor(IEnumerable<byte> a, byte b)
        {
            return Xor(a, Repeat(b));
        }

        public static IDictionary<char, int> GetCharacterCounts(string value)
        {
            return value.GroupBy(c => c).ToDictionary(group => group.Key, group => group.Count());
        }

        public static IDictionary<char, double> GetCharacterFrequency(string value)
        {
            var counts = GetCharacterCounts(value);
            var total = counts.Sum(entry => entry.Value);
            return counts.ToDictionary(kv => kv.Key, kv => (double) kv.Value/total);
        }

        public static double Distance(IDictionary<char, double> frequencies1, IDictionary<char, double> frequencies2)
        {
            var joined = frequencies1.FullOuterJoin(frequencies2, pair => pair.Key, pair => pair.Key,
                (pair, valuePair, key) => (pair.Value - valuePair.Value)*(pair.Value - valuePair.Value));

            return Math.Sqrt(joined.Sum());
        }

        public static double Distance(double[] vector1, double[] vector2)
        {
            return Math.Sqrt(vector1.Zip(vector2, (a, b) => (a - b)*(a - b)).Sum());
        }

        public static int Hamming(IEnumerable<byte> value1, IEnumerable<byte> value2)
        {
            return value1.Zip(value2, Hamming).Sum();
        }

        public static int Hamming(byte value1, byte value2)
        {
            var union = value1 ^ value2;

            int count = 0;
            while (union != 0)
            {
                if ((union & 1) != 0)
                    count++;
                union = union >> 1;
            }

            return count;
        }

        public static IEnumerable<byte> PadPkcs7(this IEnumerable<byte> value, byte blockSize)
        {
            int count = 0;
            foreach (var b in value)
            {
                yield return b;
                count++;
            }

            var remainder = blockSize%count;

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

            if(!padding.All(b => b == paddingLength))
                throw new InvalidOperationException("Invalid padding");

            for (int i = 0; i < dataLength; i++)
                yield return data[i];
        }

        public static IDictionary<char, double> GetNewYorkTimesCharacterFrequency()
        {
            string text = GetResourceText("Turing.txt");
            return GetCharacterFrequency(text);
        }

        public static IEnumerable<string> GetResourceLines(string resourceName)
        {
            var assembly = Assembly.GetExecutingAssembly();
            using (var stream = assembly.GetManifestResourceStream($"MatasanoCryptoChallenge.Resources.{resourceName}"))
            using (var reader = new StreamReader(stream))
            {
                string line;

                while ((line = reader.ReadLine()) != null)
                {
                    yield return line;
                }
            }
        }

        public static string GetResourceText(string resourceName)
        {
            var assembly = Assembly.GetExecutingAssembly();
            using (var stream = assembly.GetManifestResourceStream($"MatasanoCryptoChallenge.Resources.{resourceName}"))
            using (var reader = new StreamReader(stream))
            {
                return reader.ReadToEnd();
            }
        }

        public static byte[] GetResourceBase64(string resouceName)
        {
            var base64 = GetResourceText(resouceName).Replace("\n", string.Empty);
            return Convert.FromBase64String(base64);
        }

        public static IEnumerable<byte[]> GetResourceBase64Lines(string resouceName)
        {
            return GetResourceLines(resouceName).Select(Convert.FromBase64String);
        } 

        private static IEnumerable<byte> Repeat(byte value)
        {
            while (true)
                yield return value;
        }

    }
}