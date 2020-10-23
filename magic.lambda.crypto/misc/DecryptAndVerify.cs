/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.IO;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Engines;
using magic.node;
using magic.node.extensions;
using magic.signals.contracts;

namespace magic.lambda.crypto.misc
{
    /// <summary>
    /// [crypto.decrypt-and-verify] slot that decrypts and verifies the
    /// specified content using the specified arguments.
    /// </summary>
    [Slot(Name = "crypto.decrypt-and-verify")]
    public class DecryptAndVerify : ISlot
    {
        public void Signal(ISignaler signaler, Node input)
        {
            var content = Utilities.GetContent(input);
            var decryptionKey = Utilities.GetKeyFromArguments(input, "decryption-key");
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;

            // House cleaning.
            input.Clear();
            input.Value = null;

            // Decrypting content and returning to caller.
            var result = DecryptContentRawContent(
                content,
                decryptionKey);
            if (raw)
            {
                input.Value = result.Content;
                input.Add(new Node("signature", result.Signature));
            }
            else
            {
                input.Value = Encoding.UTF8.GetString(result.Content);
                input.Add(new Node("signature", Convert.ToBase64String(result.Signature)));
            }
            input.Add(new Node("fingerprint", result.Fingerprint));
        }

        #region [ -- Private helper methods -- ]

        (byte[] Content, byte[] Signature, string Fingerprint) DecryptContentRawContent(
            byte[] content,
            byte[] privateKey)
        {
            // The first 32 bytes is the fingerprint of our self public key.
            using (var encStream = new MemoryStream(content))
            {
                // Simplifying life.
                var encReader = new BinaryReader(encStream);

                var messageFingerprint = encReader.ReadBytes(32);

                // Reading AES key.
                var encryptedAesKeyLength = encReader.ReadInt32();
                var encryptedAesKey = encReader.ReadBytes(encryptedAesKeyLength);

                // Decrypting AES key.
                var decryptedAesKey = DecryptAesKey(encryptedAesKey, privateKey);

                // Decrypting main body of message.
                using (var encContentStream = new MemoryStream())
                {
                    encStream.CopyTo(encContentStream);
                    var encryptedBytes = encContentStream.ToArray();
                    var decryptedContent = DecryptContent(encryptedBytes, decryptedAesKey);
                    using (var decryptedContentStream = new MemoryStream(decryptedContent))
                    {
                        var decryptedReader = new BinaryReader(decryptedContentStream);
                        var sendersPublicKeySha256 = decryptedReader.ReadBytes(32);
                        var lengthOfSignature = decryptedReader.ReadInt32();
                        var signature = decryptedReader.ReadBytes(lengthOfSignature);
                        var fingerprint = CreateFingerprint(sendersPublicKeySha256);
                        var lengthOfPlainTextContent = decryptedReader.ReadInt32();
                        var result = decryptedReader.ReadBytes(lengthOfPlainTextContent);
                        return (result, signature, fingerprint);
                    }
                }
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

        /*
         * Decrypts the specified AES key using the specified private RSA key.
         */
        byte[] DecryptAesKey(byte[] encryptedAesKey, byte[] privateRsaKey)
        {
            return Utilities.DecryptMessage(
                encryptedAesKey,
                PrivateKeyFactory.CreateKey(privateRsaKey),
                new RsaEngine());
        }

        byte[] DecryptContent(byte[] aesEncryptedContent, byte[] aesKey)
        {
            return Utilities.Decrypt(aesKey, aesEncryptedContent);
        }

        #endregion
    }
}
