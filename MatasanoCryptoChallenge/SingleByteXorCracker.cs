using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace MatasanoCryptoChallenge
{
    public static class SingleByteXorCracker
    {
        public static string Crack(IEnumerable<byte> cipherData, out double error)
        {
            byte key;
            return Crack(cipherData, out error, out key);
        }

        public static string Crack(IEnumerable<byte> cipherData, out double error, out byte key)
        {
            var keys = Enumerable.Range(0, sbyte.MaxValue).Select(Convert.ToByte);

            var plainData = keys.ToDictionary(k => k, k => Utils.Xor(cipherData, k).ToArray());
            var plainTexts = plainData.ToDictionary(pair => pair.Key, pair => Encoding.ASCII.GetString(pair.Value));
            var frequencies = plainTexts.ToDictionary(pair => pair.Key, pair => Utils.GetCharacterFrequency(pair.Value));

            var nytFrequency = Utils.GetNewYorkTimesCharacterFrequency();

            var distances =
                frequencies.ToDictionary(pair => pair.Key, pair => Utils.Distance(nytFrequency, pair.Value))
                    .OrderBy(pair => pair.Value);
            var bestMatch = distances.First();
            key = bestMatch.Key;

            error = bestMatch.Value;

            return plainTexts[key];
        }
    }
}
