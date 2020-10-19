/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Encodings;
using magic.node;
using magic.signals.contracts;

namespace magic.lambda.crypto.rsa
{
    /// <summary>
    /// [crypto.rsa.encrypt] slot to encrypt some content using a public key that can only be decrypted
    /// using its public key.
    /// </summary>
    [Slot(Name = "crypto.rsa.encrypt")]
    public class RsaEncrypt : ISlot
    {
        /// <summary>
        /// Implementation of slot.
        /// </summary>
        /// <param name="signaler">Signaler invoking slot.</param>
        /// <param name="input">Arguments to slot.</param>
        public void Signal(ISignaler signaler, Node input)
        {
            // Retrieving arguments.
            var message = Utilities.GetEncryptionMessage(input);

            // Converting key from base64 encoded DER format.
            var publicKey = Utilities.GetPublicKey(input);

            // Performing actual encryption, and returning results to caller.
            Utilities.CreateEncryptionResult(
                input,
                new Pkcs1Encoding(new RsaEngine()),
                publicKey,
                message);
        }
    }
}
