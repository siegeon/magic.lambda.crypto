/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.IO;
using System.Text;
using System.Linq;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using magic.node;
using magic.node.extensions;
using magic.signals.contracts;

namespace magic.lambda.crypto.aes
{
    /// <summary>
    /// [crypto.aes.decrypt] slot to decrypt some content using a symmetric cryptography algorithm (AES),
    /// that was previously encrypted using the same algorithm.
    /// </summary>
    [Slot(Name = "crypto.aes.decrypt")]
    public class AesDecrypt : ISlot
    {
        const int MAC_SIZE = 128;
        const int NONCE_SIZE = 12;

        /// <summary>
        /// Implementation of slot.
        /// </summary>
        /// <param name="signaler">Signaler invoking slot.</param>
        /// <param name="input">Arguments to slot.</param>
        public void Signal(ISignaler signaler, Node input)
        {
            // Retrieving arguments.
            var rawMessage = input.GetEx<object>();
            var message = rawMessage is string strMsg ? Convert.FromBase64String(strMsg) : rawMessage as byte[];
            var password = Encoding.UTF8.GetBytes(input.Children.FirstOrDefault(x => x.Name == "password")?.GetEx<string>() ??
                throw new ArgumentException("No [password] provided to [crypto.aes.encrypt]"));
            var strength = input.Children.FirstOrDefault(x => x.Name == "strength")?.GetEx<int>() ?? 128;
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;
            input.Clear();

            // Performing actual decryption.
            var result = Decrypt(password, message, strength);

            if (raw)
                input.Value = result;
            else
                input.Value = Encoding.UTF8.GetString(result);
        }

        #region [ -- Internal helper methods -- ]

        /*
         * AES decrypts the specified data, using the specified password.
         */
        static byte[] Decrypt(byte[] password, byte[] data, int strength)
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

        #endregion
    }
}
