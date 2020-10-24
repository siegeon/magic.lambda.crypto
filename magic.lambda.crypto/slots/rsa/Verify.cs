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
using magic.lambda.crypto.rsa;
using magic.lambda.crypto.utilities;

namespace magic.lambda.crypto.slots.rsa
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
            // Retrieving arguments.
            var rawMessage = input.GetEx<object>();
            var message = rawMessage is string strMsg ? Encoding.UTF8.GetBytes(strMsg) : rawMessage as byte[];

            var rawSignature = input.Children.FirstOrDefault(x => x.Name == "signature")?.GetEx<object>();
            var signature = rawSignature is string strSign ? Convert.FromBase64String(strSign) : rawSignature as byte[];

            var algo = input.Children.FirstOrDefault(x => x.Name == "algorithm")?.GetEx<string>() ?? "SHA256";
            var key = Utilities.GetKeyFromArguments(input, "public-key");
            input.Clear();
            input.Value = null;

            var verifier = new Verifier(key);
            verifier.Verify(algo, message, signature);
        }
    }
}
