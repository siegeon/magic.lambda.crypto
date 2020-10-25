/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace magic.lambda.crypto.utilities
{
    /*
     * Utility class to provide common functions for other classes and methods.
     */
    internal static class Utilities
    {
        /*
         * Creates a string fingerprint from the specified content by creating
         * a SHA256 of the specified content, and then returning the hash in
         * fingerprint format to the caller.
         */
        internal static string CreateSha256Fingerprint(byte[] content)
        {
            using (var hash = SHA256.Create())
            {
                var hashed = hash.ComputeHash(content);
                return CreateFingerprint(hashed);
            }
        }

        /*
         * Creates a fingerprint representation of the specified byte[] content.
         */
        internal static string CreateFingerprint(byte[] content)
        {
            // Sanity checking invocation.
            if (content.Length != 32)
                throw new ArgumentException($"Cannot create a fingerprint from your content, since it was {content.Length} long. It must be 32 bytes.");

            // Creating a fingerprint in the format of "09fe-de45-..." of the 32 bytes long argument.
            var result = new StringBuilder();
            var idxNo = 0;
            foreach (var idx in content)
            {
                result.Append(BitConverter.ToString(new byte[] { idx }));
                if (++idxNo % 2 == 0)
                    result.Append("-");
            }
            return result.ToString().TrimEnd('-').ToLowerInvariant();
        }

        /*
         * Returns fingerprint of key used to encrypt message.
         */
        public static byte[] GetPackageFingerprint(byte[] content)
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
         * Helper method to generate a 256 bits 32 byte[] long key from a passphrase.
         */
        internal static byte[] Generate256BitKey(string passphrase)
        {
            using (var hash = SHA256.Create())
            {
                return hash.ComputeHash(Encoding.UTF8.GetBytes(passphrase));
            }
        }
    }
}
