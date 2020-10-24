/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using Org.BouncyCastle.Crypto.Engines;
using magic.node;
using magic.signals.contracts;
using ut = magic.lambda.crypto.rsa.utilities;

namespace magic.lambda.crypto.slots.rsa
{
    /// <summary>
    /// [crypto.rsa.decrypt] slot to decrypt some content using a private key that was previously
    /// encrypted using a public key.
    /// </summary>
    [Slot(Name = "crypto.rsa.decrypt")]
    public class Decrypt : ISlot
    {
        /// <summary>
        /// Implementation of slot.
        /// </summary>
        /// <param name="signaler">Signaler invoking slot.</param>
        /// <param name="input">Arguments to slot.</param>
        public void Signal(ISignaler signaler, Node input)
        {
            ut.Decrypter.DecryptMessage(input, new RsaEngine());
        }
    }
}
