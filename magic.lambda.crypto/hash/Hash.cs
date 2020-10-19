/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using magic.node;
using magic.node.extensions;
using magic.signals.contracts;

namespace magic.lambda.crypto.hash
{
    /// <summary>
    /// [crypto.hash] slot to create a cryptographically secure hash of a piece of string.
    /// </summary>
    [Slot(Name = "crypto.hash")]
    public class Hash : ISlot
    {
        /// <summary>
        /// Implementation of slot.
        /// </summary>
        /// <param name="signaler">Signaler invoking slot.</param>
        /// <param name="input">Arguments to slot.</param>
        public void Signal(ISignaler signaler, Node input)
        {
            var text = input.GetEx<string>();
            var algorithm = input.Children.FirstOrDefault(x => x.Name == "algorithm")?.GetEx<string>() ?? "SHA256";
            switch (algorithm)
            {
                case "SHA256":
                    using (var algo = SHA256Managed.Create())
                    {
                        input.Value = GenerateHash(algo, text);
                    }
                    break;
                case "SHA384":
                    using (var algo = SHA384Managed.Create())
                    {
                        input.Value = GenerateHash(algo, text);
                    }
                    break;
                case "SHA512":
                    using (var algo = SHA512Managed.Create())
                    {
                        input.Value = GenerateHash(algo, text);
                    }
                    break;
                default:
                    throw new ArgumentException($"'{algorithm}' is an unknown hashing algorithm.");
            }
        }

        #region [ -- Private helper methods -- ]

        string GenerateHash(HashAlgorithm algo, string text)
        {
            var bytes = algo.ComputeHash(Encoding.UTF8.GetBytes(text));
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }

        #endregion
    }
}
