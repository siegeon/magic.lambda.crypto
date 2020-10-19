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
    /// [crypto.rsa.decrypt] slot to decrypt some content using a private key.
    /// </summary>
    [Slot(Name = "crypto.rsa.decrypt")]
    public class RsaDecrypt : ISlot
    {
        /// <summary>
        /// Implementation of slot.
        /// </summary>
        /// <param name="signaler">Signaler invoking slot.</param>
        /// <param name="input">Arguments to slot.</param>
        public void Signal(ISignaler signaler, Node input)
        {
            // Retrieving arguments.
            var message = Helpers.GetDecryptionMessage(input);

            // Converting key from base64 encoded DER format.
            var privateKey = Helpers.GetPrivateKey(input);

            var encryptEngine = new Pkcs1Encoding(new RsaEngine());
            encryptEngine.Init(false, privateKey);
            Helpers.CreateDecryptionResult(input, encryptEngine.ProcessBlock(message, 0, message.Length));
        }
    }
}
