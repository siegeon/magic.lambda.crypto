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
using Org.BouncyCastle.Crypto.Encodings;
using magic.node;
using magic.node.extensions;
using Org.BouncyCastle.Crypto.Paddings;

namespace magic.lambda.crypto
{
    /*
     * Utility class to provide common functions for other classes and methods.
     */
    internal static class Utilities
    {
        /*
         * Creates a new keypair using the specified key pair generator, and returns the key pair to caller.
         */
        internal static void CreateNewKeyPair(Node input, IAsymmetricCipherKeyPairGenerator generator)
        {
            // Retrieving arguments, if given, or supplying sane defaults if not.
            var strength = input.Children.FirstOrDefault(x => x.Name == "strength")?.GetEx<int>() ?? 2048;
            var seed = input.Children.FirstOrDefault(x => x.Name == "seed")?.GetEx<string>();
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;

            // Clearing existing node, to avoid returning garbage back to caller.
            input.Clear();

            // Initializing our generator according to caller's specifications.
            var rnd = new SecureRandom();
            if (seed != null)
                rnd.SetSeed(Encoding.UTF8.GetBytes(seed));
            generator.Init(new KeyGenerationParameters(rnd, strength));

            // Creating keypair.
            var keyPair = generator.GenerateKeyPair();
            var privateInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
            var publicInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);

            // Returning key pair according to caller's specifications.
            if (raw)
            {
                // Returning as DER encoded raw byte[].
                input.Add(new Node("public", publicInfo.GetDerEncoded()));
                input.Add(new Node("private", privateInfo.GetDerEncoded()));
            }
            else
            {
                // Returning as base64 encoded DER format.
                input.Add(new Node("public", Convert.ToBase64String(publicInfo.GetDerEncoded())));
                input.Add(new Node("private", Convert.ToBase64String(privateInfo.GetDerEncoded())));
            }
        }

        /*
         * Encrypts a message using the specified engine, and returns result to
         * caller, according to caller's specifications.
         */
        internal static void EncryptMessage(Node input, IAsymmetricBlockCipher engine)
        {
            // Retrieving message and other arguments.
            var rawMessage = input.GetEx<object>();
            var message = rawMessage is string strMsg ? Encoding.UTF8.GetBytes(strMsg) : rawMessage as byte[];
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;
            var publicKey = GetPublicKey(input);
            input.Clear();

            // Creating our encryption engine, and decorating according to caller's specifications.
            var encryptionEngine = new Pkcs1Encoding(engine);
            encryptionEngine.Init(true, publicKey);

            // Encrypting message, and returning results to according to caller's specifications.
            var result = encryptionEngine.ProcessBlock(message, 0, message.Length);
            if (raw)
                input.Value = result;
            else
                input.Value = Convert.ToBase64String(result);
        }

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
            var privateKey = GetPrivateKey(input);
            input.Clear();

            // Creating our encryption engine, and decorating according to caller's specifications.
            var encryptEngine = new Pkcs1Encoding(engine);
            encryptEngine.Init(false, privateKey);

            // Decrypting message, and returning results to according to caller's specifications.
            var result = encryptEngine.ProcessBlock(message, 0, message.Length);
            if (raw)
                input.Value = result;
            else
                input.Value = Encoding.UTF8.GetString(result);
        }

        /*
         * Cryptographically signs the specified message, according to caller's specifications.
         */
        internal static void SignMessage(Node input)
        {
            // Retrieving arguments.
            var rawMessage = input.GetEx<object>();
            var message = rawMessage is string strMsg ? Encoding.UTF8.GetBytes(strMsg) : rawMessage as byte[];
            var algo = input.Children.FirstOrDefault(x => x.Name == "algorithm")?.GetEx<string>() ?? "SHA256";
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;
            var privateKey = GetPrivateKey(input);
            input.Clear();

            // Creating our signer and associating it with the private key.
            var sig = SignerUtilities.GetSigner($"{algo}withRSA");
            sig.Init(true, privateKey);

            // Signing the specified data, and returning to caller according to specifications.
            sig.BlockUpdate(message, 0, message.Length);
            byte[] signature = sig.GenerateSignature();
            if (raw)
                input.Value = signature;
            else
                input.Value = Convert.ToBase64String(signature);
        }

        /*
         * Verifies a cryptographic signature, according to caller's specifications.
         */
        internal static void VerifySignature(Node input)
        {
            // Retrieving arguments.
            var rawMessage = input.GetEx<object>();
            var message = rawMessage is string strMsg ? Encoding.UTF8.GetBytes(strMsg) : rawMessage as byte[];
            var rawSignature = input.Children.FirstOrDefault(x => x.Name == "signature")?.GetEx<object>();
            var signature = rawSignature is string strSign ? Convert.FromBase64String(strSign) : rawSignature as byte[];
            var algo = input.Children.FirstOrDefault(x => x.Name == "algorithm")?.GetEx<string>() ?? "SHA256";
            var key = GetPublicKey(input);
            input.Clear();
            input.Value = null;

            // Creating our signer and associating it with the private key.
            var sig = SignerUtilities.GetSigner($"{algo}withRSA");
            sig.Init(false, key);

            // Signing the specified data, and returning to caller as base64.
            sig.BlockUpdate(message, 0, message.Length);
            if (!sig.VerifySignature(signature))
                throw new ArgumentException("Signature mismatch in [crypto.rsa.verify]");
        }

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
