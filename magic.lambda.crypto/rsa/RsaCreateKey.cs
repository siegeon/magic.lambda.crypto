/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using Org.BouncyCastle.Crypto.Generators;
using magic.node;
using magic.signals.contracts;

namespace magic.lambda.crypto.rsa
{
    /// <summary>
    /// [crypto.rsa.create-key] slot to create an RSA keypair and return as DER encoded,
    /// optionally base64 encoding results.
    /// </summary>
    [Slot(Name = "crypto.rsa.create-key")]
    public class RsaCreateKey : ISlot
    {
        /// <summary>
        /// Implementation of slot.
        /// </summary>
        /// <param name="signaler">Signaler invoking slot.</param>
        /// <param name="input">Arguments to slot.</param>
        public void Signal(ISignaler signaler, Node input)
        {
            Utilities.CreateNewKeyPair(input, new RsaKeyPairGenerator());
        }
    }
}
