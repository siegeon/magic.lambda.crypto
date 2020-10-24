/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System.Linq;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using magic.node;
using magic.node.extensions;
using magic.signals.contracts;
using magic.lambda.crypto.rsa;
using ut = magic.lambda.crypto.utilities;
using System;

namespace magic.lambda.crypto.slots.rsa
{
    /// <summary>
    /// [crypto.rsa.encrypt] slot to encrypt some content using a public key that can only be decrypted
    /// using its public key.
    /// </summary>
    [Slot(Name = "crypto.rsa.encrypt")]
    public class Encrypt : ISlot
    {
        /// <summary>
        /// Implementation of slot.
        /// </summary>
        /// <param name="signaler">Signaler invoking slot.</param>
        /// <param name="input">Arguments to slot.</param>
        public void Signal(ISignaler signaler, Node input)
        {
            // Retrieving message and other arguments.
            var rawMessage = input.GetEx<object>();
            var message = rawMessage is string strMsg ? Encoding.UTF8.GetBytes(strMsg) : rawMessage as byte[];

            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;
            var key = ut.Utilities.GetPublicKey(input);
            var publicKey = ut.Utilities.GetKeyFromArguments(input, "public-key");

            var rsaEncrypter = new Encrypter(publicKey);
            var result = rsaEncrypter.Encrypt(message);
            input.Value = raw ? result : (object)Convert.ToBase64String(result);
            input.Clear();
        }
    }
}
