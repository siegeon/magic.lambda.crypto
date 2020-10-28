/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Linq;
using magic.node;
using magic.node.extensions;
using magic.signals.contracts;
using magic.crypto.combinations;

namespace magic.lambda.crypto.slots.combinations
{
    /// <summary>
    /// [crypto.sign] slot that signs the specified content using the spcified arguments.
    /// </summary>
    [Slot(Name = "crypto.sign")]
    public class Sign : ISlot
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

            // Signing content.
            var signer = new Signer(arguments.SigningKey, arguments.SigningKeyFingerprint);
            var signed = signer.Sign(arguments.Content);

            // Returning results to caller.
            input.Value = arguments.Raw ? (object)signed : Convert.ToBase64String(signed);
        }

        #region [ -- Private helper methods -- ]

        /*
         * Retrieves arguments for invocation.
         */
        (byte[] Content, byte[] SigningKey, byte[] SigningKeyFingerprint, bool Raw) GetArguments(Node input)
        {
            var content = Utilities.GetContent(input);
            var signingKey = Utilities.GetKeyFromArguments(input, "signing-key");
            var signingKeyFingerprint = GetFingerprint(input);
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;
            input.Clear();
            return (content, signingKey, signingKeyFingerprint, raw);
        }

        /*
         * Returns byte[] representation of fingerprint used in invocation.
         */
        byte[] GetFingerprint(Node input)
        {
            // Sanity checking invocation.
            var nodes = input.Children.Where(x => x.Name == "signing-key-fingerprint");
            if (nodes.Count() != 1)
                throw new ArgumentException($"You must provide [signing-key-fingerprint]");

            // Retrieving key, making sure we support both base64 encoded, and raw byte[] keys.
            var result = nodes.First()?.GetEx<object>();
            if (result is byte[] resultRaw)
            {
                if (resultRaw.Length != 32)
                    throw new ArgumentException("Fingerprint is not 32 bytes long");
                return resultRaw;
            }
            else
            {
                var resultFingerprint = (result as string).Replace("-", "");
                int noChars = resultFingerprint.Length;
                byte[] bytes = new byte[noChars / 2];
                for (int i = 0; i < noChars; i += 2)
                {
                    bytes[i / 2] = Convert.ToByte(resultFingerprint.Substring(i, 2), 16);
                }
                if (bytes.Length != 32)
                    throw new ArgumentException("Fingerprint is not 32 bytes long");
                return bytes;
            }
        }

        #endregion
    }
}
