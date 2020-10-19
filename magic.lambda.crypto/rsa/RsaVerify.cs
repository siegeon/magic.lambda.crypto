/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Linq;
using System.Text;
using magic.node;
using magic.node.extensions;
using magic.signals.contracts;
using Org.BouncyCastle.Security;

namespace magic.lambda.crypto.rsa
{
    /// <summary>
    /// [crypto.rsa.verify] slot to verify that some piece of text was cryptographically
    /// signed with a specific private key.
    /// </summary>
    [Slot(Name = "crypto.rsa.verify")]
    public class RsaVerify : ISlot
    {
        /// <summary>
        /// Implementation of slot.
        /// </summary>
        /// <param name="signaler">Signaler invoking slot.</param>
        /// <param name="input">Arguments to slot.</param>
        public void Signal(ISignaler signaler, Node input)
        {
            // Retrieving arguments.
            var message = Encoding.UTF8.GetBytes(input.GetEx<string>());
            var signature = Convert.FromBase64String(
                input.Children.FirstOrDefault(x => x.Name == "signature")?.GetEx<string>()) ??
                throw new ArgumentException("No [signature] supplied to [crypto.rsa.verify]");
            var algo = input.Children.FirstOrDefault(x => x.Name == "algorithm")?.GetEx<string>() ?? "SHA256";

            // Converting key from base64 encoded DER format.
            var key = Helpers.GetPublicKey(input);

            // Creating our signer and associating it with the private key.
            var sig = SignerUtilities.GetSigner($"{algo}withRSA");
            sig.Init(false, key);

            // Signing the specified data, and returning to caller as base64.
            sig.BlockUpdate(message, 0, message.Length);
            if (!sig.VerifySignature(signature))
                throw new ArgumentException("Signature mismatch in [crypto.rsa.verify]");
            input.Clear();
            input.Value = null;
        }
    }
}
