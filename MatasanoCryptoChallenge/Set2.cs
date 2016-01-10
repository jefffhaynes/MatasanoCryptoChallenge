using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace MatasanoCryptoChallenge
{
    [TestClass]
    public class Set2
    {
        [TestMethod]
        public void Challenge09_ImplementPkcs7()
        {
            var data = Encoding.ASCII.GetBytes("YELLOW SUBMARINE");
            var padded = data.PadPkcs7(20);

            var expected = data.Concat(new byte[] {0x04, 0x04, 0x04, 0x04});

            Assert.IsTrue(expected.SequenceEqual(padded));
        }

        [TestMethod]
        public void Challenge10_ImplementCbc()
        {
            var cipherData = Utils.GetResourceBase64("ImplementCbcMode.txt");
            const string key = "YELLOW SUBMARINE";
            var keyData = Encoding.ASCII.GetBytes(key);
            var iv = Enumerable.Repeat((byte)0, 16).ToArray();

            var decryptor = new AesCbcCryptoTransform(keyData, iv);

            var cipherStream = new MemoryStream(cipherData);

            using (var cryptoStream = new CryptoStream(cipherStream, decryptor, CryptoStreamMode.Read))
            using (var reader = new StreamReader(cryptoStream))
            {
                var plainText = reader.ReadToEnd();
                var expected = Utils.GetResourceText("Set2PlainText.txt");

                Assert.AreEqual(expected, plainText);
            }
        }
    }
}
