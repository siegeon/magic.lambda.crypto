/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using Org.BouncyCastle.Security;

namespace magic.lambda.crypto.utilities
{
    /*
     * Helper class to sign and encrypt a plain text message.
     */
    internal class Encrypter
    {
        readonly byte[] _encryptionKey;
        readonly byte[] _signingKey;
        readonly byte[] _signingKeyFingerprint;
        readonly SecureRandom _csrng;

        public Encrypter(
            byte[] encryptionKey,
            byte[] signingKey,
            byte[] signingKeyFingerprint,
            string seed)
            : this (
                encryptionKey,
                signingKey,
                signingKeyFingerprint,
                string.IsNullOrEmpty(seed) ? null : Encoding.UTF8.GetBytes(seed))
        { }

        /*
         * Creates a new plain text message.
         */
        public Encrypter(
            byte[] encryptionKey,
            byte[] signingKey,
            byte[] signingKeyFingerprint,
            byte[] seed = null)
        {
            // Sanity checking invocation, fingerprint should be SHA256 of signing key's public sibling.
            if (signingKeyFingerprint.Length != 32)
                throw new ArgumentException("Signing key's fingerprint was not valid");

            // Creating our CS RNG instance.
            _csrng = new SecureRandom();
            if (seed != null)
                _csrng.SetSeed(seed);

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
            var signed = Sign(
                content,
                _signingKeyFingerprint,
                _signingKey);

            // Encrypting content, and returning to caller.
            return Encrypt(signed, _encryptionKey);
        }

        #region [ -- Private helper methods -- ]

        /*
         * Creates and returns signed plain content of message.
         */
        byte[] Sign(
            byte[] content,
            byte[] signingKeyFingerprint,
            byte[] signingKey)
        {
            // Creating plain text stream.
            using (var stream = new MemoryStream())
            {
                // Simplifying life.
                var writer = new BinaryWriter(stream);

                // Writing SHA256 of fingerprint key.
                writer.Write(signingKeyFingerprint);

                // Writing signature.
                var signer = SignerUtilities.GetSigner($"SHA256withRSA");
                var signature =  rsa.Signer.Sign(
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
        byte[] Encrypt(
            byte[] content,
            byte[] encryptionKey)
        {
            // Creating encryption stream.
            using (var encStream = new MemoryStream())
            {
                // Simplifying life.
                var encWriter = new BinaryWriter(encStream);

                // Writing encryption key's fingerprint.
                var fingerprint = CreateSha256(encryptionKey);
                encWriter.Write(fingerprint);

                // Writing encrypted AES key.
                var aesKey = CreateAesKey();
                var rsaEncrypter = new rsa.Encrypter(encryptionKey); 
                var encryptedAesKey = rsaEncrypter.Encrypt(aesKey);
                encWriter.Write(encryptedAesKey.Length);
                encWriter.Write(encryptedAesKey);

                // Writing encrypted content.
                var aesEcnrypter = new aes.Encrypter(aesKey);
                var encrypted = aesEcnrypter.Encrypt(content);
                encWriter.Write(encrypted);
                return encStream.ToArray();
            }
        }

        /*
         * Creates a symmetric AES encryption key, to encrypt payload.
         */
        byte[] CreateAesKey()
        {
            var bytes = new byte[32];
            _csrng.NextBytes(bytes);
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
