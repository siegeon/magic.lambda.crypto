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
using magic.lambda.crypto.combinations;

namespace magic.lambda.crypto.slots.combinations
{
    /// <summary>
    /// [crypto.decrypt] slot that decrypts and verifies the
    /// specified content using the specified arguments.
    /// 
    /// This slots assumes the message was encrypted using its [crypto.encrypt] equivalent.
    /// </summary>
    [Slot(Name = "crypto.decrypt")]
    public class Decrypt : ISlot
    {
        /// <summary>
        /// Implementation of slot.
        /// </summary>
        /// <param name="signaler">Signaler invoking slot.</param>
        /// <param name="input">Arguments to slot.</param>
        public void Signal(ISignaler signaler, Node input)
        {
            // Retrieving arguments.
            var arguments = GetArguments(input);

            // Decrypting content.
            var decrypter = new Decrypter(arguments.DecryptionKey);
            var decrypted = decrypter.Decrypt(arguments.Content);

            // Verifying content, which implies splitting the content, signature, and signing key.
            var verifier = new Verifier(null);
            var result = verifier.Verify(decrypted);

            // Returning result to caller.
            if (arguments.Raw)
            {
                input.Value = result.Content;
                input.Add(new Node("signature", result.Signature));
            }
            else
            {
                input.Value = Encoding.UTF8.GetString(result.Content);
                input.Add(new Node("signature", Convert.ToBase64String(result.Signature)));
            }
            input.Add(new Node("fingerprint", result.Fingerprint));
        }

        #region [ -- Private helper methods -- ]

        /*
         * Retrieves arguments for invocation.
         */
        (byte[] Content, byte[] DecryptionKey, bool Raw) GetArguments(Node input)
        {
            var content = Utilities.GetContent(input, true);
            var decryptionKey = Utilities.GetKeyFromArguments(input, "decryption-key");
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;
            input.Clear();
            return (content, decryptionKey, raw);
        }

        #endregion
    }
}
