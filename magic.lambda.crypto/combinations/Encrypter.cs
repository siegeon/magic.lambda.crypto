/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System.IO;
using System.Text;
using Org.BouncyCastle.Security;
using magic.lambda.crypto.utilities;

namespace magic.lambda.crypto.combinations
{
    /*
     * Helper class to encrypt a plain text message.
     */
    internal class Encrypter
    {
        readonly byte[] _encryptionKey;
        readonly SecureRandom _csrng;

        public Encrypter(byte[] encryptionKey, string seed)
            : this (encryptionKey, string.IsNullOrEmpty(seed) ? null : Encoding.UTF8.GetBytes(seed))
        { }

        /*
         * Creates a new plain text message.
         */
        public Encrypter(byte[] encryptionKey, byte[] seed = null)
        {
            // Creating our CS RNG instance.
            _csrng = new SecureRandom();
            if (seed != null)
                _csrng.SetSeed(seed);

            _encryptionKey = encryptionKey;
        }

        /*
         * Signs and encrypts the message, and returns as raw cipher to caller.
         */
        public byte[] Encrypt(byte[] content)
        {
            // Creating encryption stream.
            using (var encStream = new MemoryStream())
            {
                // Simplifying life.
                var encWriter = new BinaryWriter(encStream);

                // Writing encryption key's fingerprint.
                var fingerprint = Utilities.CreateSha256(_encryptionKey);
                encWriter.Write(fingerprint);

                // Writing encrypted AES key.
                var aesKey = CreateAesKey();
                var rsaEncrypter = new rsa.Encrypter(_encryptionKey); 
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

        #region [ -- Private helper methods -- ]

        /*
         * Creates a symmetric AES encryption key, to encrypt payload.
         */
        byte[] CreateAesKey()
        {
            var bytes = new byte[32];
            _csrng.NextBytes(bytes);
            return bytes;
        }

        #endregion
    }
}
