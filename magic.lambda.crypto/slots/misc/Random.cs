﻿/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2021, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System.Linq;
using System.Text;
using Org.BouncyCastle.Security;
using magic.node;
using magic.node.extensions;
using magic.signals.contracts;

namespace magic.lambda.crypto.slots.misc
{
    /// <summary>
    /// [crypto.random] slot to create a bunch of cryptographically secured random characters.
    /// </summary>
    [Slot(Name = "crypto.random")]
    public class Random : ISlot
    {
        const string _alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        /// <summary>
        /// Implementation of slot.
        /// </summary>
        /// <param name="signaler">Signaler invoking slot.</param>
        /// <param name="input">Arguments to slot.</param>
        public void Signal(ISignaler signaler, Node input)
        {
            // Retrieving arguments.
            var min = input.Children.FirstOrDefault(x => x.Name == "min")?.GetEx<int>() ?? 10;
            var max = input.Children.FirstOrDefault(x => x.Name == "max")?.GetEx<int>() ?? 20;
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;
            var seed = input.Children.FirstOrDefault(x => x.Name == "seed")?.GetEx<string>();

            // Creating a new CSRNG, seeding it if caller provided a [seed].
            var rnd = new SecureRandom();
            if (!string.IsNullOrEmpty(seed))
                rnd.SetSeed(Encoding.UTF8.GetBytes(seed));

            // Retrieving a random number of bytes, between min/max values provided by caller.
            var bytes = new byte[rnd.Next(min, max)];
            rnd.NextBytes(bytes);

            // Returning in the format requested by caller.
            input.Value = raw ? (object)bytes : string.Concat(bytes.Select(x => _alphabet[x % (_alphabet.Length)]));
        }
    }
}
