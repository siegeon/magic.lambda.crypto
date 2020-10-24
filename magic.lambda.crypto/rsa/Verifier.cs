/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Security;
using magic.node;
using magic.node.extensions;
using magic.lambda.crypto.utilities;

namespace magic.lambda.crypto.rsa
{
    /*
     * Utility class to provide common functions for other classes and methods.
     */
    internal static class Verifier
    {
        /*
         * Verifies a cryptographic signature, according to caller's specifications.
         */
        internal static void Verify(Node input, string encryptionAlgorithm)
        {
            // Retrieving arguments.
            var rawMessage = input.GetEx<object>();
            var message = rawMessage is string strMsg ? Encoding.UTF8.GetBytes(strMsg) : rawMessage as byte[];

            var rawSignature = input.Children.FirstOrDefault(x => x.Name == "signature")?.GetEx<object>();
            var signature = rawSignature is string strSign ? Convert.FromBase64String(strSign) : rawSignature as byte[];

            var algo = input.Children.FirstOrDefault(x => x.Name == "algorithm")?.GetEx<string>() ?? "SHA256";
            var key = Utilities.GetPublicKey(input);
            input.Clear();
            input.Value = null;

            // Creating our signer and associating it with the private key.
            var signer = SignerUtilities.GetSigner($"{algo}with{encryptionAlgorithm}");
            signer.Init(false, key);

            // Signing the specified data, and returning to caller as base64.
            signer.BlockUpdate(message, 0, message.Length);
            if (!signer.VerifySignature(signature))
                throw new ArgumentException("Signature mismatch");
        }
    }
}
