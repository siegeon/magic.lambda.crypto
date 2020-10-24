/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Encodings;
using magic.node;
using magic.node.extensions;
using magic.lambda.crypto.utilities;

namespace magic.lambda.crypto.rsa.utilities
{
    /*
     * Utility class to provide common functions for other classes and methods.
     */
    internal static class Decrypter
    {
        /*
         * Decrypts a message using the specified engine, and returns result to
         * caller, according to caller's specifications.
         */
        internal static void DecryptMessage(Node input, IAsymmetricBlockCipher engine)
        {
            // Retrieving message and other arguments.
            var rawMessage = input.GetEx<object>();
            var message = rawMessage is string strMsg ? Convert.FromBase64String(strMsg) : rawMessage as byte[];

            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;
            var privateKey = Utilities.GetPrivateKey(input);
            input.Clear();

            // Decrypting message, and returning results to according to caller's specifications.
            var result = DecryptMessage(message, privateKey, new RsaEngine());
            if (raw)
                input.Value = result;
            else
                input.Value = Encoding.UTF8.GetString(result);
        }

        /*
         * Decrypts the specified message accordint to the specified arguments.
         */
        internal static byte[] DecryptMessage(
            byte[] message,
            AsymmetricKeyParameter key,
            IAsymmetricBlockCipher engine)
        {
            // Creating our encryption engine, and decorating according to caller's specifications.
            var encryptEngine = new Pkcs1Encoding(engine);
            encryptEngine.Init(false, key);

            // Decrypting message, and returning results to according to caller's specifications.
            var result = encryptEngine.ProcessBlock(message, 0, message.Length);
            return result;
        }
    }
}
