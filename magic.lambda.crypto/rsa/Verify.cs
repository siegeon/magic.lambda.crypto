/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using magic.node;
using magic.signals.contracts;
using magic.lambda.crypto.rsa.utilities;

namespace magic.lambda.crypto.rsa
{
    /// <summary>
    /// [crypto.rsa.verify] slot to verify that some piece of text was cryptographically
    /// signed with a specific private key.
    /// </summary>
    [Slot(Name = "crypto.rsa.verify")]
    public class Verify : ISlot
    {
        /// <summary>
        /// Implementation of slot.
        /// </summary>
        /// <param name="signaler">Signaler invoking slot.</param>
        /// <param name="input">Arguments to slot.</param>
        public void Signal(ISignaler signaler, Node input)
        {
            Verifier.VerifySignature(input, "RSA");
        }
    }
}
