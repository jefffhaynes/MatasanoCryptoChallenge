using System;
using System.Linq;
using System.Security.Cryptography;

namespace MatasanoCryptoChallenge
{
    public class AesCbcCryptoTransform : ICryptoTransform
    {
        private readonly byte[] _previousBlock;
        private readonly ICryptoTransform _aesEcbTransform;

        public AesCbcCryptoTransform(byte[] key, byte[] iv)
        {
            var aes = new AesManaged
            {
                Mode = CipherMode.ECB,
                Padding = PaddingMode.None
            };

            _aesEcbTransform = aes.CreateDecryptor(key, new byte[aes.BlockSize/8]);
            _previousBlock = iv;
        }

        public void Dispose()
        {
            _aesEcbTransform.Dispose();
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if (inputCount != InputBlockSize)
                throw new ArgumentException("Input count does not match input block size");
            
            var output = new byte[OutputBlockSize];
            var length = _aesEcbTransform.TransformBlock(inputBuffer, inputOffset, inputCount, output, 0);

            var outputPlusPreviousBlock = Utils.Xor(output, _previousBlock).ToArray();
            Array.Copy(outputPlusPreviousBlock, 0, outputBuffer, outputOffset, length);
            Array.Copy(inputBuffer, inputOffset, _previousBlock, 0, length);

            return length;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            var output =  _aesEcbTransform.TransformFinalBlock(inputBuffer, inputOffset, inputCount);
            return output.Length == 0 ? output : output.RemovePkcs7().ToArray();
        }

        public int InputBlockSize => _aesEcbTransform.InputBlockSize;
        public int OutputBlockSize => _aesEcbTransform.OutputBlockSize;
        public bool CanTransformMultipleBlocks => false;
        public bool CanReuseTransform => true;
    }
}
