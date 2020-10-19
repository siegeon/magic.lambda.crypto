/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Text;
using System.Linq;
using System.Security.Cryptography;
using magic.node;
using magic.node.extensions;
using magic.signals.contracts;

namespace magic.lambda.crypto.misc
{
    /// <summary>
    /// [crypto.random] slot to create a bunch of cryptographically secured random characters.
    /// </summary>
    [Slot(Name = "crypto.random")]
    public class RandomBytes : ISlot
    {
        const string _valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        /// <summary>
        /// Implementation of slot.
        /// </summary>
        /// <param name="signaler">Signaler invoking slot.</param>
        /// <param name="input">Arguments to slot.</param>
        public void Signal(ISignaler signaler, Node input)
        {
            var min = input.Children.FirstOrDefault(x => x.Name == "min")?.GetEx<int>() ?? 10;
            var max = input.Children.FirstOrDefault(x => x.Name == "max")?.GetEx<int>() ?? 20;
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;
            var result = new StringBuilder();
            using (var rng = new RNGCryptoServiceProvider())
            {
                var bytes = new byte[new Random().Next(min, max)];
                rng.GetBytes(bytes);
                if (raw)
                {
                    // Caller wants raw bytes.
                    input.Value = bytes;
                    return;
                }
                foreach (var idx in bytes)
                {
                    result.Append(_valid[idx % (_valid.Length - 1)]);
                }
            }
            input.Value = result.ToString();
        }
    }
}
