/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Security.Cryptography;
using magic.node;
using magic.node.extensions;
using magic.signals.contracts;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Security;

namespace magic.lambda.crypto.aes
{
    /// <summary>
    /// [crypto.aes.decrypt] slot to decrypt some content using a symmetric cryptography algorithm (AES),
    /// that was previously encrypted using the same algorithm.
    /// </summary>
    [Slot(Name = "crypto.aes.decrypt")]
    public class AesDecrypt : ISlot
    {
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
            using (var cipherStream = new MemoryStream(data))
            using (var cipherReader = new BinaryReader(cipherStream))
            {
                var nonce = cipherReader.ReadBytes(strength / 8);
                var cipher = new GcmBlockCipher(new AesEngine());
                var parameters = new AeadParameters(new KeyParameter(password), strength, nonce, null);
                cipher.Init(false, parameters);
                var cipherText = cipherReader.ReadBytes(data.Length - nonce.Length);
                var plainText = new byte[cipher.GetOutputSize(cipherText.Length)];
                var len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0);
                cipher.DoFinal(plainText, len);
                return plainText;
            }
        }

        #endregion
    }
}
