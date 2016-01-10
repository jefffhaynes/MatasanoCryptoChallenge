using System;
using System.Linq;
using System.Security.Cryptography;

namespace MatasanoCryptoChallenge
{
    public class XorCryptoTransform : ICryptoTransform
    {
        public XorCryptoTransform(byte[] key)
        {
            Key = key;
        }

        public byte[] Key { get; }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if(inputCount != InputBlockSize)
                throw new ArgumentException("Input count does not match input block size");

            var input = inputBuffer.Skip(inputOffset).Take(inputCount);

            var output = Utils.Xor(input, Key).ToArray();
            Array.Copy(output, 0, outputBuffer, outputOffset, output.Length);

            return output.Length;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            var input = inputBuffer.Skip(inputOffset).Take(inputCount);
            var key = Key.Take(inputCount);
            return Utils.Xor(input, key).ToArray();
        }

        public int InputBlockSize => Key.Length;
        public int OutputBlockSize => Key.Length;
        public bool CanTransformMultipleBlocks => false;
        public bool CanReuseTransform => true;

        public void Dispose()
        {
        }
    }
}
