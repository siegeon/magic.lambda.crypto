/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System.Text;
using System.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using magic.node;
using magic.node.extensions;
using magic.signals.contracts;
using System.Runtime.CompilerServices;

namespace magic.lambda.crypto.rsa
{
    /// <summary>
    /// [crypto.rsa.create-key] slot to create an RSA keypair.
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
            // Creating keypair generator, and seeding the SecureRandom if seed was given.
            var generator = new RsaKeyPairGenerator();
            generator.Init(Utilities.CreateKeyGenerateParameters(input));

            // Returning key pair to caller.
            Utilities.ReturnKeyPair(input, generator.GenerateKeyPair());
        }
    }
}
