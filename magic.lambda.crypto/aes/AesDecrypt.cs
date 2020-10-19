/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using magic.node;
using magic.node.extensions;
using magic.signals.contracts;
using System.Linq;

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
            byte[] vector = new byte[16];
            byte[] encryptedContent = new byte[data.Length - 16];

            // TODO: Optimise, no need to block copy here, just read from stream before instantiating CryptoStream (I think).
            Buffer.BlockCopy(data, 0, vector, 0, vector.Length);
            Buffer.BlockCopy(data, vector.Length, encryptedContent, 0, encryptedContent.Length);

            using (var stream = new MemoryStream())
            {
                using (var aes = new AesManaged())
                {
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.KeySize = strength;
                    aes.BlockSize = 128;

                    using (var cryptoStream = new CryptoStream(stream, aes.CreateDecryptor(password, vector), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(encryptedContent, 0, encryptedContent.Length);
                    }
                    return stream.ToArray();
                }
            }
        }

        #endregion
    }
}
