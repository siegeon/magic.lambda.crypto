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
    /// [crypto.rsa.sign] slot to cryptographically sign some piece of data with some
    /// private RSA key.
    /// </summary>
    [Slot(Name = "crypto.rsa.sign")]
    public class Sign : ISlot
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

            var algo = input.Children.FirstOrDefault(x => x.Name == "algorithm")?.GetEx<string>() ?? "SHA256";
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;
            var key = Utilities.GetKeyFromArguments(input, "private-key");

            var signer = new Signer(key);
            var signature = signer.Sign(algo, message);
            input.Value = raw ? signature : (object)Convert.ToBase64String(signature);
        }
    }
}
