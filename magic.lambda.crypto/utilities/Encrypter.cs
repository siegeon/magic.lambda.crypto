/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Engines;

namespace magic.lambda.crypto
{
    /*
     * Helper class to sign and encrypt a plain text message.
     */
    internal class Encrypter
    {
        readonly byte[] _encryptionKey;
        readonly byte[] _signingKey;
        readonly byte[] _signingKeyFingerprint;

        /*
         * Creates a new plain text message.
         */
        public Encrypter(
            byte[] encryptionKey,
            byte[] signingKey,
            byte[] signingKeyFingerprint)
        {
            _encryptionKey = encryptionKey;
            _signingKey = signingKey;
            _signingKeyFingerprint = signingKeyFingerprint;
        }

        /*
         * Signs and encrypts the message, and returns as raw cipher to caller.
         */
        public byte[] SignAndEncrypt(byte[] content)
        {
            // Signing content.
            var rawPlain = Sign(
                content,
                _signingKeyFingerprint,
                _signingKey);

            // Encrypting content, and returning to caller.
            return Encrypt(
                rawPlain,
                _encryptionKey);
        }

        #region [ -- Private helper methods -- ]

        /*
         * Creates and returns plain text content of message.
         *
         * Returns an array of f(signing_key_fingerprint + signature + content).
         */
        static byte[] Sign(
            byte[] content,
            byte[] fingerprint,
            byte[] signingKey)
        {
            // Creating plain text stream.
            using (var stream = new MemoryStream())
            {
                // Simplifying life.
                var writer = new BinaryWriter(stream);

                // Writing SHA256 of fingerprint key.
                writer.Write(fingerprint);

                // Writing signature.
                var signer = SignerUtilities.GetSigner($"SHA256withRSA");
                var signature =  Utilities.SignMessage(
                    signer,
                    content,
                    PrivateKeyFactory.CreateKey(signingKey));
                writer.Write(signature.Length);
                writer.Write(signature);

                // Writing content.
                writer.Write(content);
                return stream.ToArray();
            }
        }

        /*
         * Creates encrypted content from the given argument.
         */
        static byte[] Encrypt(
            byte[] plain,
            byte[] encryptionKey)
        {
            // Creating encryption stream.
            using (var encStream = new MemoryStream())
            {
                // Simplifying life.
                var encWriter = new BinaryWriter(encStream);

                // Writing encryption key's fingerprint.
                encWriter.Write(CreateSha256(encryptionKey));

                // Writing encrypted AES key.
                var aesKey = CreateSymmetricEncryptionKey();
                var encryptedAesKey = Utilities.EncryptMessage(
                    new RsaEngine(),
                    aesKey,
                    PublicKeyFactory.CreateKey(encryptionKey));
                encWriter.Write(encryptedAesKey.Length);
                encWriter.Write(encryptedAesKey);

                // Writing encrypted content.
                var encrypted = Utilities.AesEncrypt(aesKey, plain);
                encWriter.Write(encrypted);
                return encStream.ToArray();
            }
        }

        /*
         * Creates a symmetric AES encryption key, to encrypt payload.
         */
        static byte[] CreateSymmetricEncryptionKey()
        {
            var rnd = new SecureRandom();
            var bytes = new byte[32];
            rnd.NextBytes(bytes);
            return bytes;
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
