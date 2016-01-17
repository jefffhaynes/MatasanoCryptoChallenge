using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace MatasanoCryptoChallenge
{
    [TestClass]
    public class Set1
    {
        [TestMethod]
        public void Challenge1_HexToBase64()
        {
            var bytes =
                Utils.HexToByteArray(
                    "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");

            var base64 = Convert.ToBase64String(bytes);

            const string expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

            Assert.AreEqual(expected, base64);
        }

        [TestMethod]
        public void Challenge2_FixedXor()
        {
            const string aHex = "1c0111001f010100061a024b53535009181c";
            const string bHex = "686974207468652062756c6c277320657965";

            var aData = Utils.HexToByteArray(aHex);
            var bData = Utils.HexToByteArray(bHex);

            var result = Utils.Xor(aData, bData).ToArray();

            const string expected = "746865206b696420646f6e277420706c6179";
            var actual = BitConverter.ToString(result).Replace("-", string.Empty);

            Assert.AreEqual(expected, actual, true);
        }

        [TestMethod]
        public void Challenge3_SingleByteXorCipher()
        {
            const string cipherHex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
            var cipherData = Utils.HexToByteArray(cipherHex);

            double error;
            var plainText = SingleByteXorCracker.Crack(cipherData, out error);

            const string expected = "Cooking MC's like a pound of bacon";

            Assert.AreEqual(expected, plainText);
        }

        [TestMethod]
        public void Challenge4_DetectSingleCharacterXor()
        {
            var lines = Utils.GetResourceLines("DetectSingleCharacterXor.txt");
            var lineData = lines.Select(Utils.HexToByteArray);
            var errors = lineData.Select(line =>
            {
                double error;
                var result = SingleByteXorCracker.Crack(line, out error);
                return new {Result = result, Error = error};
            }).OrderBy(line => line.Error);

            var best = errors.First();

            const string expected = "Now that the party is jumping\n";

            Assert.AreEqual(expected, best.Result);
        }


        [TestMethod]
        public void Challenge5Prep_RoundtripXor()
        {
            const string plaintext = "We have nothing to fear but fear itself";

            var transform = new XorCryptoTransform(Encoding.ASCII.GetBytes("the key!"));

            var stream = new MemoryStream();
            using (var writerStream = new CryptoStream(stream, transform, CryptoStreamMode.Write))
            using (var writer = new StreamWriter(writerStream, Encoding.ASCII, 4096, true))
                writer.Write(plaintext);

            var cipherStream = new MemoryStream(stream.ToArray());

            using (var readerStream = new CryptoStream(cipherStream, transform, CryptoStreamMode.Read))
            using (var reader = new StreamReader(readerStream))
                Assert.AreEqual(plaintext, reader.ReadToEnd());
        }

        [TestMethod]
        public void Challenge5_RepeatingKeyXor()
        {
            var key = Encoding.ASCII.GetBytes("ICE");

            const string plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

            var transform = new XorCryptoTransform(key);

            var stream = new MemoryStream();
            using (var cryptoStream = new CryptoStream(stream, transform, CryptoStreamMode.Write))
            {
                using (var writer = new StreamWriter(cryptoStream))
                    writer.Write(plaintext);
            }
            
            var expected =
                Utils.HexToByteArray(
                    "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");

            var actual = stream.ToArray();

            Assert.IsTrue(expected.SequenceEqual(actual));
        }

        [TestMethod]
        public void Challenge6Prep_HammingTest()
        {
            const string value1 = "this is a test";
            const string value2 = "wokka wokka!!!";

            var hamming = Utils.Hamming(Encoding.ASCII.GetBytes(value1), Encoding.ASCII.GetBytes(value2));

            const int expected = 37;

            Assert.AreEqual(expected, hamming);
        }

        [TestMethod]
        public void Challenge6_BreakRepeatingKeyXor()
        {
            var data = Utils.GetResourceBase64("RepeatingKeyXor.txt");

            var keySizes = Enumerable.Range(2, 40);
            
            // this is slightly different than the approach described in the challenge.  We 
            // convolve the data against itself and look for the lowest "energy" step.  This
            // is likely where the repeating keys overlap and the plaintext pattern emerges.
            var convolvedKeySizes = keySizes.ToDictionary(keySize => keySize, keySize =>
            {
                var padding = Enumerable.Repeat((byte) 0, keySize).ToArray();
                return Utils.Hamming(padding.Concat(data), data.Concat(padding));
            }).OrderBy(pair => pair.Value);

            var topKeySizes = convolvedKeySizes.Select(pair => pair.Key).Take(1);

            // distribute data into bins that align with first key byte, second key byte, etc.
            var transposedBlocks =
                topKeySizes.Select(
                    keySize =>
                        Enumerable.Range(0, keySize)
                            .Select(keyOffset => data.Where((x, i) => i % keySize == keyOffset).ToArray()));

            var keySizeKeyErrors = transposedBlocks.Select(pair => pair.Select(k =>
                {
                    byte key;
                    double error;
                    var result = SingleByteXorCracker.Crack(k, out error, out key);
                    return new { Result = result, Key = key, Error = error };
                }));

            var possibleKeys = keySizeKeyErrors.Select(k => k.Select(r => r.Key).ToArray());

            var plaintexts = possibleKeys.ToDictionary(key => key, key =>
            {
                var transform = new XorCryptoTransform(key);

                var stream = new MemoryStream(data);
                using (var cryptoStream = new CryptoStream(stream, transform, CryptoStreamMode.Read))
                {
                    using (var reader = new StreamReader(cryptoStream))
                        return reader.ReadToEnd();
                }
            });

            var actual = plaintexts.First().Value;

            var expected = Utils.GetResourceText("Set1PlainText.txt");

            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void Challenge7_AesEcbMode()
        {
            var aes = new AesManaged {Mode = CipherMode.ECB};

            var key = Encoding.ASCII.GetBytes("YELLOW SUBMARINE");
            var decryptor = aes.CreateDecryptor(key, new byte[aes.BlockSize/8]);

            var cipherData = Utils.GetResourceBase64("AesEcb.txt");
            var cipherStream = new MemoryStream(cipherData);

            using (var cryptoStream = new CryptoStream(cipherStream, decryptor, CryptoStreamMode.Read))
            using (var reader = new StreamReader(cryptoStream))
            {
                var plainText = reader.ReadToEnd();
                var expected = Utils.GetResourceText("Set1PlainText.txt");

                Assert.AreEqual(expected, plainText);
            }
        }

        [TestMethod]
        public void Challenge8_DetectAesEcb()
        {
            var lines = Utils.GetResourceBase64Lines("DetectAesEcb.txt");

            var padding = Enumerable.Repeat((byte)0, 16).ToArray();
            var lineDistances = lines.ToDictionary(line => line, line => Utils.Hamming(padding.Concat(line), line.Concat(padding)));

            var lowestDistance = lineDistances.OrderBy(pair => pair.Value);

            var encryptedData = lowestDistance.First().Key;

            var encryptedBase64 = Convert.ToBase64String(encryptedData);

            const string expectedBase64 =
                "fe2977f56f9f414ddf898d21b3e13a48116dbf3ed13253ee69c2005ba1afd30d0665d03e76820e172af73ee8bb3ac387170f81530d73debf97d9dc73b6f4073089ef48ef43f24b0a0e69e2ed1f469482f9c74ae3618399bf6bf99bbf9a6476ed1d3398bc9a59f90feb131b2147795c39a38ec4ab883a3732f9a4c01fd3600047973b361d60f8457e63abbd29d7d73415d89c852305649125533ad73828e34d2e";
           
            Assert.AreEqual(expectedBase64, encryptedBase64);
        }
    }
}
