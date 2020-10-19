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
     * Utility class to provide common functions for other classes and methods.
     */
    internal static class Utilities
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
         * Returns the message caller wants to encrypt as a byte[], converting
         * from string if necessary.
         */
        internal static byte[] GetEncryptionMessage(Node input)
        {
            var message = input.GetEx<object>();
            if (message is string strMessage)
                return Encoding.UTF8.GetBytes(strMessage); // Returning byte[] representation of string.

            return message as byte[]; // Assuming raw byte[] message.
        }

        /*
         * Returns the message caller wants to decrypt as a byte[], converting
         * from base64 encoding if necessary.
         */
        internal static byte[] GetDecryptionMessage(Node input)
        {
            var message = input.GetEx<object>();
            if (message is string strMessage)
                return Convert.FromBase64String(strMessage); // Assuming encrypted message was base64 encoded.

            return message as byte[]; // Assuming raw byte[] encrypted message.
        }

        /*
         * Encrypts specified message, using specified key, and specified encryption engine,
         * and returns results to caller according to specifications.
         */
        internal static void CreateEncryptionResult(
            Node input,
            IAsymmetricBlockCipher encryptionEngine,
            AsymmetricKeyParameter publicKey,
            byte[] message)
        {
            encryptionEngine.Init(true, publicKey);
            var encryptedMessage = encryptionEngine.ProcessBlock(message, 0, message.Length);
            if (input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false)
                input.Value = encryptedMessage; // Caller wants the raw byte[] result.
            else
                input.Value = Convert.ToBase64String(encryptedMessage); // Caller wants the base64 encoded version of the result.
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

        /*
         * Creates parameters for a key pair generator according to specified arguments.
         */
        internal static KeyGenerationParameters CreateKeyGenerateParameters(Node input)
        {
            // Retrieving arguments, if given, or supplying sane defaults if not.
            var strength = input.Children.FirstOrDefault(x => x.Name == "strength")?.GetEx<int>() ?? 2048;
            var seed = input.Children.FirstOrDefault(x => x.Name == "seed")?.GetEx<string>();
            var rnd = new SecureRandom();
            if (seed != null)
                rnd.SetSeed(Encoding.UTF8.GetBytes(seed));
            return new KeyGenerationParameters(rnd, strength);
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
