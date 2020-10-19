/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using magic.node;
using magic.node.extensions;

namespace magic.lambda.crypto
{
    /*
     * Helper utility class to provide common functions for other classes and methods.
     */
    internal static class Helpers
    {
        /*
         * Returns a public key according to the given arguments.
         */
        internal static AsymmetricKeyParameter GetPublicKey(Node input)
        {
            return PublicKeyFactory.CreateKey(GetKeyFromArguments(input, "public-key"));
        }

        /*
         * Returns a private key according to the given arguments.
         */
        internal static AsymmetricKeyParameter GetPrivateKey(Node input)
        {
            return PrivateKeyFactory.CreateKey(GetKeyFromArguments(input, "private-key"));
        }

        /*
         * Returns the message according to the given arguments, message her
         * is something the caller wants to encrypt.
         */
        internal static byte[] GetEncryptionMessage(Node input)
        {
            var message = input.GetEx<object>();
            if (message is string strMessage)
                return Encoding.UTF8.GetBytes(strMessage);
            return message as byte[];
        }

        /*
         * Returns the message according to the given arguments, message her
         * is something the caller wants to decrypt.
         */
        internal static byte[] GetDecryptionMessage(Node input)
        {
            var message = input.GetEx<object>();
            if (message is string strMessage)
                return Convert.FromBase64String(strMessage);
            return message as byte[];
        }

        /*
         * Returns result to caller according to the specified arguments.
         */
        internal static void CreateEncryptionResult(Node input, byte[] result)
        {
            if (input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false)
                input.Value = result;
            else
                input.Value = Convert.ToBase64String(result);
        }

        /*
         * Returns result to caller according to the specified arguments.
         */
        internal static void CreateDecryptionResult(Node input, byte[] result)
        {
            if (input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false)
                input.Value = result;
            else
                input.Value = Encoding.UTF8.GetString(result);
        }

        internal static void ReturnKeyPair(Node input, AsymmetricCipherKeyPair keyPair)
        {
            // Retrieving arguments.
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;

            // Returning keypair.
            input.Value = null;
            input.Clear();
            var privateInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
            var publicInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            if (raw)
            {
                input.Add(new Node("public", publicInfo.GetDerEncoded()));
                input.Add(new Node("private", privateInfo.GetDerEncoded()));
            }
            else
            {
                input.Add(new Node("public", Convert.ToBase64String(publicInfo.GetDerEncoded())));
                input.Add(new Node("private", Convert.ToBase64String(privateInfo.GetDerEncoded())));
            }
        }

        #region [ -- Private helper methods -- ]

        /*
         * Private helper method to return byte[] representation of key.
         */
        static byte[] GetKeyFromArguments(Node input, string keyType)
        {
            // Sanity checking invocation.
            var keys = input.Children.Where(x => x.Name == keyType || x.Name == "key");
            if (keys.Count() != 1)
                throw new ArgumentException($"You must provide exactly one key, either as [{keyType}] or as [key]");

            // Retrieving key, making sure we support both base64 encoded, and raw byte[] keys.
            var key = keys.First()?.GetEx<object>();
            if (key is string strKey)
                return Convert.FromBase64String(strKey); // base64 encoded.

            return key as byte[]; // Assuming raw byte[] key.
        }

        #endregion
    }
}
