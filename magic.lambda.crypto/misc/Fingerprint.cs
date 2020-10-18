/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Text;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using magic.node;
using magic.node.extensions;
using magic.signals.contracts;

namespace magic.lambda.crypto.misc
{
    /// <summary>
    /// [crypto.fingerprint] slot to create a fingerprint of anything requiring such.
    /// </summary>
    [Slot(Name = "crypto.fingerprint")]
    public class Fingerprint : ISlot
    {
        const string _alphabet = "abcdefghijklmnopqrstuvwxyz123456789";

        /// <summary>
        /// Implementation of slot.
        /// </summary>
        /// <param name="signaler">Signaler invoking slot.</param>
        /// <param name="input">Arguments to slot.</param>
        public void Signal(ISignaler signaler, Node input)
        {
            var text = input.GetEx<string>();
            var algorithm = input.Children.FirstOrDefault(x => x.Name == "algorithm")?.GetEx<string>() ?? "SHA256";
            var checksum = input.Children.FirstOrDefault(x => x.Name == "base")?.GetEx<long>() ?? 10007;
            byte[] raw;
            switch (algorithm)
            {
                case "SHA1":
                    using (var algo = SHA1.Create())
                    {
                        raw = GenerateHash(algo, text);
                    }
                    break;
                case "SHA256":
                    using (var algo = SHA256.Create())
                    {
                        raw = GenerateHash(algo, text);
                    }
                    break;
                case "SHA384":
                    using (var algo = SHA384.Create())
                    {
                        raw = GenerateHash(algo, text);
                    }
                    break;
                case "SHA512":
                    using (var algo = SHA512.Create())
                    {
                        raw = GenerateHash(algo, text);
                    }
                    break;
                case "MD5":
                    using (var algo = MD5.Create())
                    {
                        raw = GenerateHash(algo, text);
                    }
                    break;
                default:
                    throw new ArgumentException($"'{algorithm}' is an unknown hashing algorithm.");
            }
            var buffer = new StringBuilder();
            BigInteger exponent = 1;
            BigInteger sum = 0;
            var no = 0;
            foreach (var idx in raw.Reverse())
            {
                var eat = idx % _alphabet.Length;
                var curChar = _alphabet[eat];
                sum += (eat * exponent);
                exponent *= _alphabet.Length;
                buffer.Append(curChar);
                if (++no % 4 == 0)
                    buffer.Append(".");
            }
            input.Value = buffer.ToString() + (sum % checksum);
        }

        #region [ -- Private helper methods -- ]

        static byte[] GenerateHash(HashAlgorithm algo, string text)
        {
            return algo.ComputeHash(Encoding.UTF8.GetBytes(text));
        }

        #endregion
    }
}
