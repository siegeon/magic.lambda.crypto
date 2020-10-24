/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Linq;
using magic.node;
using magic.node.extensions;
using magic.signals.contracts;
using magic.lambda.crypto.rsa;

namespace magic.lambda.crypto.slots.rsa
{
    /// <summary>
    /// [crypto.rsa.create-key] slot to create an RSA keypair and return as DER encoded,
    /// .
    /// </summary>
    [Slot(Name = "crypto.rsa.create-key")]
    public class CreateKey : ISlot
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
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;

            // Clearing existing node, to avoid returning garbage back to caller.
            input.Clear();
            var generator = new KeyGenerator(seed);
            var result = generator.Generate(strength);
            if (raw)
            {
                // Returning as DER encoded raw byte[].
                input.Add(new Node("private", result.Private));
                input.Add(new Node("public", result.Public));
                input.Add(new Node("fingerprint", result.Fingerprint));
            }
            else
            {
                // Returning as base64 encoded DER format.
                input.Add(new Node("private", Convert.ToBase64String(result.Private)));
                input.Add(new Node("public", Convert.ToBase64String(result.Public)));
                input.Add(new Node("fingerprint", result.Fingerprint));
            }
        }
    }
}
