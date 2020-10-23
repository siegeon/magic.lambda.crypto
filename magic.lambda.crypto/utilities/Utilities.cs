/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Parameters;
using magic.node;
using magic.node.extensions;

namespace magic.lambda.crypto.utilities
{
    /*
     * Utility class to provide common functions for other classes and methods.
     */
    internal static class Utilities
    {
        const int MAC_SIZE = 128;
        const int NONCE_SIZE = 12;

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
                input.Add(new Node("private", privateInfo.GetDerEncoded()));
                input.Add(new Node("public", publicInfo.GetDerEncoded()));
            }
            else
            {
                // Returning as base64 encoded DER format.
                input.Add(new Node("private", Convert.ToBase64String(privateInfo.GetDerEncoded())));
                input.Add(new Node("public", Convert.ToBase64String(publicInfo.GetDerEncoded())));
            }
        }

        /*
         * Helper method to generate a 256 bits 32 byte[] long key from a passphrase.
         */
        internal static byte[] Generate256BitKey(string content)
        {
            using (var hash = SHA256.Create())
            {
                return hash.ComputeHash(Encoding.UTF8.GetBytes(content));
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
            var key = GetPublicKey(input);
            var cipher = EncryptMessage(engine, message, key);
            input.Value = raw ? cipher : (object)Convert.ToBase64String(cipher);
            input.Clear();
        }

        /*
         * Encrypts the specified message according to the specified arguments.
         */
        internal static byte[] EncryptMessage(
            IAsymmetricBlockCipher engine,
            byte[] message,
            AsymmetricKeyParameter key)
        {
            // Creating our encryption engine, and decorating according to caller's specifications.
            var encryptionEngine = new Pkcs1Encoding(engine);
            encryptionEngine.Init(true, key);

            // Encrypting message, and returning results to according to caller's specifications.
            var result = encryptionEngine.ProcessBlock(message, 0, message.Length);
            return result;
        }

        /*
         * AES encrypts the specified data, using the specified password, and bit strength.
         */
        internal static byte[] AesEncrypt(byte[] password, byte[] data)
        {
            // Creating our nonce, or Initial Vector (IV).
            var rnd = new SecureRandom();
            var nonce = new byte[NONCE_SIZE];
            rnd.NextBytes(nonce, 0, nonce.Length);

            // Initializing AES engine.
            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(password), MAC_SIZE, nonce, null);
            cipher.Init(true, parameters);

            // Creating buffer to hold encrypted content, and encrypting into buffer.
            var encrypted = new byte[cipher.GetOutputSize(data.Length)];
            var len = cipher.ProcessBytes(data, 0, data.Length, encrypted, 0);
            cipher.DoFinal(encrypted, len);

            // Writing nonce and encrypted data, and returning as byte[] to caller.
            using (var stream = new MemoryStream())
            {
                using (var writer = new BinaryWriter(stream))
                {
                    writer.Write(nonce);
                    writer.Write(encrypted);
                }
                return stream.ToArray();
            }
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

        /*
         * AES decrypts the specified data, using the specified password.
         */
        internal static byte[] Decrypt(byte[] password, byte[] data)
        {
            using (var stream = new MemoryStream(data))
            {
                using (var reader = new BinaryReader(stream))
                {
                    // Reading and discarding nonce.
                    var nonce = reader.ReadBytes(NONCE_SIZE);

                    // Creating and initializing AES engine.
                    var cipher = new GcmBlockCipher(new AesEngine());
                    var parameters = new AeadParameters(new KeyParameter(password), MAC_SIZE, nonce, null);
                    cipher.Init(false, parameters);

                    // Reading encrypted parts, and decrypting into result.
                    var encrypted = reader.ReadBytes(data.Length - nonce.Length);
                    var result = new byte[cipher.GetOutputSize(encrypted.Length)];
                    var len = cipher.ProcessBytes(encrypted, 0, encrypted.Length, result, 0);
                    cipher.DoFinal(result, len);

                    // Returning result as byte[].
                    return result;
                }
            }
        }

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
            var key = GetPrivateKey(input);
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

        /*
         * Verifies a cryptographic signature, according to caller's specifications.
         */
        internal static void VerifySignature(Node input, string encryptionAlgorithm)
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
            var signer = SignerUtilities.GetSigner($"{algo}with{encryptionAlgorithm}");
            signer.Init(false, key);

            // Signing the specified data, and returning to caller as base64.
            signer.BlockUpdate(message, 0, message.Length);
            if (!signer.VerifySignature(signature))
                throw new ArgumentException("Signature mismatch");
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

        /*
         * Private helper method to return byte[] representation of key.
         */
        internal static byte[] GetKeyFromArguments(Node input, string keyType)
        {
            // Sanity checking invocation.
            var keys = input.Children.Where(x => x.Name == keyType);
            if (keys.Count() != 1)
                throw new ArgumentException($"You must provide a [{keyType}]");

            // Retrieving key, making sure we support both base64 encoded, and raw byte[] keys.
            var key = keys.First()?.GetEx<object>();
            if (key is string strKey)
                return Convert.FromBase64String(strKey); // base64 encoded.

            return key as byte[]; // Assuming raw byte[] key.
        }

        /*
         * Private helper method to return byte[] representation of key.
         */
        internal static byte[] GetFingerprint(Node input, string nodeName)
        {
            // Sanity checking invocation.
            var nodes = input.Children.Where(x => x.Name == nodeName);
            if (nodes.Count() != 1)
                throw new ArgumentException($"You must provide [{nodeName}]");

            // Retrieving key, making sure we support both base64 encoded, and raw byte[] keys.
            var result = nodes.First()?.GetEx<byte[]>();
            if (result.Length != 32)
                throw new ArgumentException("Fingerprint is not 32 bytes long");
            return result;
        }

        /*
         * Returns content of node as byte[] for encryption/decryption.
         */
        internal static byte[] GetContent(Node input, bool base64 = false)
        {
            var contentObject = input.GetEx<object>() ??
                throw new ArgumentException("No content for cryptography operation");

            // Checking if content is already byte[].
            if (contentObject is byte[] bytes)
                return bytes;

            // Content is string, figuring out how to return it.
            if (base64)
                return Convert.FromBase64String((string)contentObject);
            else
                return Encoding.UTF8.GetBytes((string)contentObject);
        }
    }
}
