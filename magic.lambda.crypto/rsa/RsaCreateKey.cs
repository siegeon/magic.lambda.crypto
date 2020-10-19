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
            // Retrieving arguments, if given, or supplying sane defaults if not.
            var strength = input.Children.FirstOrDefault(x => x.Name == "strength")?.GetEx<int>() ?? 2048;
            var seed = input.Children.FirstOrDefault(x => x.Name == "seed")?.GetEx<string>();

            // Creating keypair generator, and seeding the SecureRandom if seed was given.
            var generator = new RsaKeyPairGenerator();
            var rnd = new SecureRandom();
            if (seed != null)
                rnd.SetSeed(Encoding.UTF8.GetBytes(seed));
            var parameters = new KeyGenerationParameters(rnd, strength);
            generator.Init(parameters);

            // Returning key pair to caller.
            Helpers.ReturnKeyPair(input, generator.GenerateKeyPair());
        }
    }
}
