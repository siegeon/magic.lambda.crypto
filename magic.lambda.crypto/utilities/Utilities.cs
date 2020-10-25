/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using magic.node;
using magic.node.extensions;

namespace magic.lambda.crypto.utilities
{
    /*
     * Utility class to provide common functions for other classes and methods.
     */
    internal static class Utilities
    {
        /*
         * Creates a fingerprint from the specified content.
         */
        internal static string CreateFingerprint(byte[] content)
        {
            using (var hash = SHA256.Create())
            {
                var hashed = hash.ComputeHash(content);
                var result = new StringBuilder();
                var idxNo = 0;
                foreach (var idx in hashed)
                {
                    result.Append(BitConverter.ToString(new byte[] { idx }));
                    if (++idxNo % 2 == 0)
                        result.Append("-");
                }
                return result.ToString().TrimEnd('-').ToLowerInvariant();
            }
        }

        /*
         * Helper method to generate a 256 bits 32 byte[] long key from a passphrase.
         */
        internal static byte[] Generate256BitKey(string passphrase)
        {
            using (var hash = SHA256.Create())
            {
                return hash.ComputeHash(Encoding.UTF8.GetBytes(passphrase));
            }
        }

        /*
         * Returns a public key according to the given arguments.
         */
        internal static AsymmetricKeyParameter GetPublicKey(Node input)
        {
            return PublicKeyFactory.CreateKey(GetKeyFromArguments(input, "public-key"));
        }

        /*
         * Returns a private key according to the given arguments.
         */
        internal static AsymmetricKeyParameter GetPrivateKey(Node input)
        {
            return PrivateKeyFactory.CreateKey(GetKeyFromArguments(input, "private-key"));
        }

        /*
         * Private helper method to return byte[] representation of key.
         */
        internal static byte[] GetKeyFromArguments(Node input, string keyType)
        {
            // Sanity checking invocation.
            var keys = input.Children.Where(x => x.Name == keyType);
            if (keys.Count() != 1)
                throw new ArgumentException($"You must provide a [{keyType}]");

            // Retrieving key, making sure we support both base64 encoded, and raw byte[] keys.
            var key = keys.First()?.GetEx<object>();
            if (key is string strKey)
                return Convert.FromBase64String(strKey); // base64 encoded.

            return key as byte[]; // Assuming raw byte[] key.
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
         * Private helper method to return byte[] from fingerprint.
         */
        internal static byte[] GetFingerprint(Node input, string nodeName)
        {
            // Sanity checking invocation.
            var nodes = input.Children.Where(x => x.Name == nodeName);
            if (nodes.Count() != 1)
                throw new ArgumentException($"You must provide [{nodeName}]");

            // Retrieving key, making sure we support both base64 encoded, and raw byte[] keys.
            var result = nodes.First()?.GetEx<object>();
            if (result is byte[] resultRaw)
            {
                if (resultRaw.Length != 32)
                    throw new ArgumentException("Fingerprint is not 32 bytes long");
                return resultRaw;
            }
            else
            {
                var resultFingerprint = (result as string).Replace("-", "");
                int noChars = resultFingerprint.Length;
                byte[] bytes = new byte[noChars / 2];
                for (int i = 0; i < noChars; i += 2)
                {
                    bytes[i / 2] = Convert.ToByte(resultFingerprint.Substring(i, 2), 16);
                }
                return bytes;
            }
        }

        /*
         * Returns content of node as byte[] for encryption/decryption.
         */
        internal static byte[] GetContent(Node input, bool base64 = false)
        {
            var contentObject = input.GetEx<object>() ??
                throw new ArgumentException("No content for cryptography operation");

            // Checking if content is already byte[].
            if (contentObject is byte[] bytes)
                return bytes;

            // Content is string, figuring out how to return it.
            if (base64)
                return Convert.FromBase64String((string)contentObject);
            else
                return Encoding.UTF8.GetBytes((string)contentObject);
        }
    }
}
