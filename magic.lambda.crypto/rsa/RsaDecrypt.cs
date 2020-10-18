/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Encodings;
using magic.node;
using magic.node.extensions;
using magic.signals.contracts;

namespace magic.lambda.crypto.rsa
{
    /// <summary>
    /// [crypto.rsa.decrypt] slot to decrypt some content using a private key.
    /// </summary>
    [Slot(Name = "crypto.rsa.decrypt")]
    public class RsaDecrypt : ISlot
    {
        /// <summary>
        /// Implementation of slot.
        /// </summary>
        /// <param name="signaler">Signaler invoking slot.</param>
        /// <param name="input">Arguments to slot.</param>
        public void Signal(ISignaler signaler, Node input)
        {
            // Retrieving arguments.
            var message = Convert.FromBase64String(input.GetEx<string>());
            var rawPrivateKey = input.Children.FirstOrDefault(x => x.Name == "key")?.GetEx<string>() ??
                throw new ArgumentException("No [key] supplied to [crypto.rsa.decrypt]");

            // Converting key from base64 encoded DER format.
            var privateKey = PrivateKeyFactory.CreateKey(Convert.FromBase64String(rawPrivateKey));

            var encryptEngine = new Pkcs1Encoding(new RsaEngine());
            encryptEngine.Init(false, privateKey);
            input.Value = Encoding.UTF8.GetString(encryptEngine.ProcessBlock(message, 0, message.Length));
        }
    }
}
