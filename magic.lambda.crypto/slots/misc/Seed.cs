﻿/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2021, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Text;
using Org.BouncyCastle.Security;
using magic.node;
using magic.node.extensions;
using magic.signals.contracts;

namespace magic.lambda.crypto.slots.misc
{
    /// <summary>
    /// [crypto.seed] slot allowing you to explicitly seed the CSRNG instance.
    /// </summary>
    [Slot(Name = "crypto.seed")]
    public class Seed : ISlot
    {
        /// <summary>
        /// Implementation of slot.
        /// </summary>
        /// <param name="signaler">Signaler invoking slot.</param>
        /// <param name="input">Arguments to slot.</param>
        public void Signal(ISignaler signaler, Node input)
        {
            // Retrieving arguments.
            var seedStr = input.GetEx<string>() ?? throw new ArgumentException("No value provided to [crypto.seed]");
            var seed = Encoding.UTF8.GetBytes(seedStr);
            var rnd = new SecureRandom();
            rnd.SetSeed(seed);
        }
    }
}