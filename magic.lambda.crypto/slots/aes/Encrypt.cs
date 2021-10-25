/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2021, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using magic.node;
using magic.signals.contracts;
using magic.lambda.crypto.lib.aes;

namespace magic.lambda.crypto.slots.aes
{
    /// <summary>
    /// [crypto.aes.encrypt] slot to encrypt some content using a symmetric cryptography algorithm (AES).
    /// </summary>
    [Slot(Name = "crypto.aes.encrypt")]
    public class Encrypt : ISlot
    {
        /// <summary>
        /// Implementation of slot.
        /// </summary>
        /// <param name="signaler">Signaler invoking slot.</param>
        /// <param name="input">Arguments to slot.</param>
        public void Signal(ISignaler signaler, Node input)
        {
            // Retrieving arguments.
            var arguments = Utilities.GetArguments(input, false);

            // Performing actual encryption.
            var encrypter = new Encrypter(arguments.Password);
            var result = encrypter.Encrypt(arguments.Message);

            // Returning results to caller according to specifications.
            input.Value = arguments.Raw ? (object)result : Convert.ToBase64String(result);
        }
    }
}
