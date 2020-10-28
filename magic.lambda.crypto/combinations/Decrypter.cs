/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System.IO;
using magic.lambda.crypto.utilities;

namespace magic.lambda.crypto.combinations
{
    /*
     * Helper class to decrypt and verify the signature of a message.
     */
    internal class Decrypter
    {
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
         * Decrypts the specified message.
         */
        public byte[] Decrypt(byte[] content)
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
                var rsaDecrypter = new rsa.Decrypter(_decryptionKey);
                var decryptedAesKey = rsaDecrypter.Decrypt(encryptedAesKey);

                // Reading the encrypted content.
                var encryptedContent = Utilities.ReadRestOfStream(encStream);

                // Decrypting content.
                var aesDecrypter = new aes.Decrypter(decryptedAesKey);
                var decryptedContent = aesDecrypter.Decrypt(encryptedContent);
                return decryptedContent;
            }
        }
    }
}
