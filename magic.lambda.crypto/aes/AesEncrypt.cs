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
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace magic.lambda.crypto.aes
{
    /// <summary>
    /// [crypto.aes.encrypt] slot to encrypt some content using a symmetric cryptography algorithm (AES).
    /// </summary>
    [Slot(Name = "crypto.aes.encrypt")]
    public class AesEncrypt : ISlot
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
            var message = rawMessage is string strMsg ? Encoding.UTF8.GetBytes(strMsg) : rawMessage as byte[];
            var password = Encoding.UTF8.GetBytes(input.Children.FirstOrDefault(x => x.Name == "password")?.GetEx<string>() ??
                throw new ArgumentException("No [password] provided to [crypto.aes.encrypt]"));
            var strength = input.Children.FirstOrDefault(x => x.Name == "strength")?.GetEx<int>() ?? 128;
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;
            input.Clear();

            // Performing actual encryption.
            var result = Encrypt(password, message, strength);

            if (raw)
                input.Value = result;
            else
                input.Value = Convert.ToBase64String(result);
        }

        #region [ -- Internal helper methods -- ]

        /*
         * AES encrypts the specified data, using the specified password, and bit strength.
         */
        static byte[] Encrypt(byte[] password, byte[] data, int strength)
        {
            var nonce = new byte[strength / 8];

            var rnd = new SecureRandom();
            rnd.NextBytes(nonce, 0, nonce.Length);

            var cipher = new GcmBlockCipher(new AesEngine());

            var parameters = new AeadParameters(new KeyParameter(password), strength, nonce, null);
            cipher.Init(true, parameters);
            var cipherText = new byte[cipher.GetOutputSize(data.Length)];
            var len = cipher.ProcessBytes(data, 0, data.Length, cipherText, 0);
            cipher.DoFinal(cipherText, len);
            using (var combinedStream = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(combinedStream))
                {
                    binaryWriter.Write(nonce);
                    binaryWriter.Write(cipherText);
                }
                return combinedStream.ToArray();
            }
        }

        #endregion
    }
}
