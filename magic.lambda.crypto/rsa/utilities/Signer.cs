/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using magic.node;
using magic.node.extensions;
using magic.lambda.crypto.utilities;

namespace magic.lambda.crypto.rsa.utilities
{
    /*
     * Utility class to provide common functions for other classes and methods.
     */
    internal static class Signer
    {
        /*
         * Cryptographically signs the specified message, according to caller's specifications.
         */
        internal static void SignMessage(Node input, string encryptionAlgorithm)
        {
            // Retrieving arguments.
            var rawMessage = input.GetEx<object>();
            var message = rawMessage is string strMsg ? Encoding.UTF8.GetBytes(strMsg) : rawMessage as byte[];

            var algo = input.Children.FirstOrDefault(x => x.Name == "algorithm")?.GetEx<string>() ?? "SHA256";
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;
            var key = Utilities.GetPrivateKey(input);
            var signer = SignerUtilities.GetSigner($"{algo}with{encryptionAlgorithm}");
            var cipher = SignMessage(signer, message, key);
            input.Value = raw ? cipher : (object)Convert.ToBase64String(cipher);
            input.Clear();
        }

        /*
         * Cryptographically signs the specified message.
         */
        internal static byte[] SignMessage(
            ISigner signer,
            byte[] message,
            AsymmetricKeyParameter key)
        {
            signer.Init(true, key);
            signer.BlockUpdate(message, 0, message.Length);
            byte[] signature = signer.GenerateSignature();
            return signature;
        }
    }
}
