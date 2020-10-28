/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using magic.node;
using magic.crypto.rsa;
using magic.signals.contracts;

namespace magic.lambda.crypto.slots.rsa
{
    /// <summary>
    /// [crypto.rsa.sign] slot to cryptographically sign some piece of data with some
    /// private RSA key.
    /// </summary>
    [Slot(Name = "crypto.rsa.sign")]
    public class Sign : ISlot
    {
        /// <summary>
        /// Implementation of slot.
        /// </summary>
        /// <param name="signaler">Signaler invoking slot.</param>
        /// <param name="input">Arguments to slot.</param>
        public void Signal(ISignaler signaler, Node input)
        {
            // Retrieving common arguments.
            var arguments = Utilities.GetArguments(input, false, "private-key");

            // Signing message.
            var signer = new Signer(arguments.Key);
            var signature = signer.Sign(arguments.Message);
            input.Value = arguments.Raw ? (object)signature : Convert.ToBase64String(signature);
        }
    }
}
