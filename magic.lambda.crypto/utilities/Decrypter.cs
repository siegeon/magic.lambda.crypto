/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Engines;
using magic.lambda.crypto.utilities;
using ut_rsa = magic.lambda.crypto.rsa.utilities;
using ut_aes = magic.lambda.crypto.aes.utilities;

namespace magic.lambda.crypto
{
    /*
     * Helper class to decrypt and verify the signature of a message.
     */
    internal class Decrypter
    {
        /*
         * Class encapsulating an encrypted message.
         */
        public class Message
        {
            public readonly byte[] Content;
            public readonly byte[] Signature;
            public readonly string Fingerprint;

            public Message(
                byte[] content,
                byte[] signature,
                string fingerprint)
            {
                Content = content;
                Signature = signature;
                Fingerprint = fingerprint;
            }
        }

        readonly byte[] _decryptionKey;

        /*
         * Creates a new instance that decrypts messages given
         * the specified decryption key.
         */
        public Decrypter(byte[] decryptionKey)
        {
            _decryptionKey = decryptionKey;
        }

        /*
         * Returns fingerprint of key used to encrypt message.
         */
        public static byte[] GetFingerprint(byte[] content)
        {
            // Creating decryption stream.
            using (var encStream = new MemoryStream(content))
            {
                // Simplifying life.
                var encReader = new BinaryReader(encStream);

                // Discarding encryption key's fingerprint.
                return encReader.ReadBytes(32);
            }
        }

        /*
         * Decrypts the specified message.
         */
        public Message Decrypt(byte[] content)
        {
            // Creating decryption stream.
            using (var encStream = new MemoryStream(content))
            {
                // Simplifying life.
                var encReader = new BinaryReader(encStream);

                // Discarding encryption key's fingerprint.
                encReader.ReadBytes(32);

                // Reading encrypted AES key.
                var encryptedAesKey = encReader.ReadBytes(encReader.ReadInt32());

                // Decrypting AES key.
                var decryptedAesKey = ut_rsa.Decrypter.DecryptMessage(
                    encryptedAesKey,
                    PrivateKeyFactory.CreateKey(_decryptionKey),
                    new RsaEngine());

                // Reading the encrypted content.
                var encryptedContent = ReadRestOfStream(encStream);

                // Decrypting content.
                var decryptedContent = ut_aes.Decrypter.Decrypt(decryptedAesKey, encryptedContent);

                // Reading decrypted content and returning results to caller.
                using (var decryptedContentStream = new MemoryStream(decryptedContent))
                {
                    // Simplifying life.
                    var decryptedReader = new BinaryReader(decryptedContentStream);

                    // Reading signing key.
                    var signingKey = decryptedReader.ReadBytes(32);
                    var fingerprint = CreateFingerprint(signingKey);

                    // Reading signature.
                    var lengthOfSignature = decryptedReader.ReadInt32();
                    var signature = decryptedReader.ReadBytes(lengthOfSignature);

                    // Reading decrypted content.
                    var result = ReadRestOfStream(decryptedContentStream);

                    // Returning a new message to caller, encapsulating decrypted message.
                    return new Message(result, signature, fingerprint);
                }
            }
        }

        #region [ -- Private helper methods -- ]

        /*
         * Read the rest of the specified stream, and returns result to caller.
         */
        byte[] ReadRestOfStream(Stream stream)
        {
            using (var tmp = new MemoryStream())
            {
                stream.CopyTo(tmp);
                return tmp.ToArray();
            }
        }

        /*
         * Creates a fingerprint from a raw byte[] array.
         */
        string CreateFingerprint(byte[] raw)
        {
            var result = new StringBuilder();
            var idxNo = 0;
            foreach (var idx in raw)
            {
                result.Append(BitConverter.ToString(new byte[] { idx }));
                if (++idxNo % 2 == 0)
                    result.Append("-");
            }
            return result.ToString().TrimEnd('-').ToLowerInvariant();
        }

        #endregion
    }
}
