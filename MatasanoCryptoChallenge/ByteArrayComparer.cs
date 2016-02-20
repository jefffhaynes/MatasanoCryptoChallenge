using System;
using System.Collections.Generic;
using System.Linq;

namespace MatasanoCryptoChallenge
{
    public class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        public bool Equals(byte[] left, byte[] right)
        {
            if (left == null || right == null)
            {
                return left == right;
            }
            if (left.Length != right.Length)
            {
                return false;
            }
            return !left.Where((t, i) => t != right[i]).Any();
        }
        public int GetHashCode(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            return key.Aggregate(0, (current, cur) => current + cur);
        }
    }
}
