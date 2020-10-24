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
using magic.lambda.crypto.utilities;

namespace magic.lambda.crypto.slots.aes
{
    /// <summary>
    /// [crypto.aes.decrypt] slot to decrypt some content using a symmetric cryptography algorithm (AES),
    /// that was previously encrypted using the same algorithm.
    /// </summary>
    [Slot(Name = "crypto.aes.decrypt")]
    public class Decrypt : ISlot
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
            var rawPassword = input.Children.FirstOrDefault(x => x.Name == "password")?.GetEx<object>() ??
                throw new ArgumentException("No [password] provided to [crypto.aes.encrypt]");
            var password = rawPassword is string strPwd ? Utilities.Generate256BitKey(strPwd) : rawPassword as byte[];
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;
            input.Clear();

            // Performing actual decryption.
            var result = Implementation(password, message);

            // Returning results to caller according to specifications.
            input.Value = raw ? (object)result : Encoding.UTF8.GetString(result);
        }

        /*
         * AES decrypts the specified data, using the specified password.
         */
        internal static byte[] Implementation(byte[] password, byte[] data)
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
    }
}
