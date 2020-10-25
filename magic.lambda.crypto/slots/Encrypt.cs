/*
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
using ut = magic.lambda.crypto.utilities;

namespace magic.lambda.crypto.slots
{
    /// <summary>
    /// [crypto.encrypt] slot that signs and encrypts the specified
    /// content using the spcified arguments.
    /// 
    /// This slot will first cryptographically sign the message, then encrypt it,
    /// resulting in a format you can read about in the project's README.md file.
    /// </summary>
    [Slot(Name = "crypto.encrypt")]
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
            var arguments = GetArguments(input);

            // Creating an encrypter.
            var encrypter = new Encrypter(
                arguments.EncryptionKey,
                arguments.SigningKey,
                arguments.SigningKeyFingerprint,
                arguments.Seed);

            // Signing and encrypting content.
            var rawResult = encrypter.SignAndEncrypt(arguments.Content);

            // Returning results to caller.
            input.Value = arguments.Raw ? (object)rawResult : Convert.ToBase64String(rawResult);
        }

        #region [ -- Private helper methods -- ]

        (byte[] Content, byte[] SigningKey, byte[] EncryptionKey, byte[] SigningKeyFingerprint, byte[] Seed, bool Raw) GetArguments(Node input)
        {
            var content = ut.Utilities.GetContent(input);
            var signingKey = ut.Utilities.GetKeyFromArguments(input, "signing-key");
            var encryptionKey = ut.Utilities.GetKeyFromArguments(input, "encryption-key");
            var signingKeyFingerprint = ut.Utilities.GetFingerprint(input, "signing-key-fingerprint");
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;
            var seedRaw = input.Children.FirstOrDefault(x => x.Name == "seed")?.GetEx<object>();
            var seed = seedRaw is string strSeed ? Encoding.UTF8.GetBytes(strSeed) : seedRaw as byte[];
            input.Clear();
            return (content, signingKey, encryptionKey, signingKeyFingerprint, seed, raw);
        }

        #endregion
    }
}
