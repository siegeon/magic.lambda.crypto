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
    /// [crypto.rsa.sign] slot to cryptographically sign some piece of
    /// data with some private RSA key.
    /// </summary>
    [Slot(Name = "crypto.rsa.sign")]
    public class RsaSign : ISlot
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
            var rawPrivateKey = input.Children.FirstOrDefault(x => x.Name == "key")?.GetEx<string>() ??
                throw new ArgumentException("No [key] supplied to [crypto.rsa.sign]");
            var algo = input.Children.FirstOrDefault(x => x.Name == "algorithm")?.GetEx<string>() ?? "SHA256";
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;

            // Converting key from base64 encoded DER format.
            var privateKey = PrivateKeyFactory.CreateKey(Convert.FromBase64String(rawPrivateKey));

            // Creating our signer and associating it with the private key.
            var sig = SignerUtilities.GetSigner($"{algo}withRSA");
            sig.Init(true, privateKey);

            // Signing the specified data, and returning to caller as base64.
            sig.BlockUpdate(message, 0, message.Length);
            byte[] signature = sig.GenerateSignature();
            if (raw)
                input.Value = signature;
            else
                input.Value = Convert.ToBase64String(signature);
            input.Clear();
        }
    }
}
