/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Engines;
using magic.node;
using magic.node.extensions;
using magic.signals.contracts;

namespace magic.lambda.crypto.misc
{
    /// <summary>
    /// [crypto.sign-and-encrypt] slot that signs and encrypts the specified
    /// content using the spcified arguments.
    /// </summary>
    [Slot(Name = "crypto.sign-and-encrypt")]
    public class SignAndEncrypt : ISlot
    {
        /// <summary>
        /// Implementation of slot.
        /// </summary>
        /// <param name="signaler">Signaler invoking slot.</param>
        /// <param name="input">Arguments to slot.</param>
        public void Signal(ISignaler signaler, Node input)
        {
            var content = Utilities.GetContent(input);
            var signingKey = Utilities.GetKeyFromArguments(input, "signing-key");
            var encryptionKey = Utilities.GetKeyFromArguments(input, "encryption-key");
            var fingerprint = Utilities.GetFingerprintFromArguments(input, "signing-key-fingerprint");
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;

            // Encrypting content and returning to caller.
            input.Clear();
            var rawContent = EncryptAndSign(
                content,
                signingKey,
                encryptionKey,
                fingerprint);
            input.Value = raw ? rawContent : (object)Convert.ToBase64String(rawContent);
        }

        #region [ -- Private helper methods -- ]

        /*
         * Encrypts and signs the specified payload according
         * to the specified arguments.
         */
        byte[] EncryptAndSign(
            byte[] content,
            byte[] signingKey,
            byte[] encryptionKey,
            byte[] fingerprint)
        {
            using (var stream = new MemoryStream())
            {
                // Simplifying life.
                var writer = new BinaryWriter(stream);

                // Writing SHA256 of fingerprint key.
                writer.Write(fingerprint);

                // Writing signature.
                var signature = Sign(content, signingKey);
                writer.Write(signature.Length);
                writer.Write(signature);

                // Writing content.
                writer.Write(content.Length);
                writer.Write(content);

                // Creating encryption stream.
                using (var encStream = new MemoryStream())
                {
                    // Simplifying life.
                    var encWriter = new BinaryWriter(encStream);

                    // Writing encryption key's fingerprint.
                    encWriter.Write(CreateSha256(encryptionKey));

                    // Writing encrypted AES key.
                    var aesKey = CreateSymmetricEncryptionKey();
                    var encryptedAesKey = RsaEncryptAesKey(aesKey, encryptionKey);
                    encWriter.Write(encryptedAesKey.Length);
                    encWriter.Write(encryptedAesKey);

                    // Writing encrypted content.
                    var encrypted = AesEncryptContent(aesKey, stream.ToArray());
                    encWriter.Write(encrypted);
                    return encStream.ToArray();
                }
            }
        }

        /*
         * Encrypts AES key with specified private RSA key.
         */
        byte[] RsaEncryptAesKey(byte[] content, byte[] key)
        {
            return Utilities.EncryptMessage(
                new RsaEngine(),
                content,
                PublicKeyFactory.CreateKey(key));
        }

        /*
         * Creates a symmetric AES encryption key, to encrypt payload.
         */
        byte[] CreateSymmetricEncryptionKey()
        {
            var rnd = new SecureRandom();
            var bytes = new byte[32];
            rnd.NextBytes(bytes);
            return bytes;
        }

        /*
         * Signs the specified content with the specified private key.
         */
        byte[] Sign(byte[] content, byte[] key)
        {
            var signer = SignerUtilities.GetSigner($"SHA256withRSA");
            return Utilities.SignMessage(
                signer,
                content,
                PrivateKeyFactory.CreateKey(key));
        }

        /*
         * AES encrypts the specified content with the specified AES key.
         */
        byte[] AesEncryptContent(byte[] aesKey, byte[] content)
        {
            return Utilities.AesEncrypt(aesKey, content);
        }

        /*
         * Returns a SHA256 of the specified data.
         */
        static internal byte[] CreateSha256(byte[] data)
        {
            using (var algo = SHA256Managed.Create())
            {
                return algo.ComputeHash(data);
            }
        }

        #endregion
    }
}
