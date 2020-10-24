/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Parameters;
using magic.node;
using magic.node.extensions;

namespace magic.lambda.crypto.aes.utilities
{
    /*
     * Utility class to provide common functions for other classes and methods.
     */
    internal static class Encrypter
    {
        const int MAC_SIZE = 128;
        const int NONCE_SIZE = 12;

        /*
         * AES encrypts the specified data, using the specified password, and bit strength.
         */
        internal static byte[] Encrypt(byte[] password, byte[] data)
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
    }
}
