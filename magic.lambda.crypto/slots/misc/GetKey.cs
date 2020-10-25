﻿/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Text;
using System.Linq;
using magic.node;
using magic.node.extensions;
using magic.signals.contracts;
using magic.lambda.crypto.utilities;

namespace magic.lambda.crypto.slots.misc
{
    /// <summary>
    /// [crypto.get-key] slot that returns the fingerprint of the encryption key
    /// that was used to encrypt a message.
    /// </summary>
    [Slot(Name = "crypto.get-key")]
    public class GetKey : ISlot
    {
        /// <summary>
        /// Implementation of slot.
        /// </summary>
        /// <param name="signaler">Signaler invoking slot.</param>
        /// <param name="input">Arguments to slot.</param>
        public void Signal(ISignaler signaler, Node input)
        {
            // Retrieving arguments.
            var content = Utilities.GetContent(input, true);
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;

            // Retrieving fingerprint.
            var fingerprint = Utilities.GetPackageFingerprint(content);

            // Returning results to caller.
            if (raw)
                input.Value = fingerprint;
            else
                input.Value = Utilities.CreateFingerprint(fingerprint);
        }
    }
}
