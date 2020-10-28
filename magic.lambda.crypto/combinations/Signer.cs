/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.IO;
using Org.BouncyCastle.Security;

namespace magic.lambda.crypto.combinations
{
    /*
     * Helper class to sign and encrypt a plain text message.
     */
    internal class Signer
    {
        readonly byte[] _signingKey;
        readonly byte[] _signingKeyFingerprint;

        /*
         * Creates a new plain text message.
         */
        public Signer(byte[] signingKey, byte[] signingKeyFingerprint)
        {
            // Sanity checking invocation, fingerprint should be SHA256 of signing key's public sibling.
            if (signingKeyFingerprint.Length != 32)
                throw new ArgumentException("Signing key's fingerprint was not valid");

            _signingKey = signingKey;
            _signingKeyFingerprint = signingKeyFingerprint;
        }

        /*
         * Creates and returns signed plain content of message.
         */
        public byte[] Sign(byte[] content)
        {
            // Creating plain text stream.
            using (var stream = new MemoryStream())
            {
                // Simplifying life.
                var writer = new BinaryWriter(stream);

                // Writing SHA256 of fingerprint key.
                writer.Write(_signingKeyFingerprint);

                // Writing signature.
                var signer = SignerUtilities.GetSigner($"SHA256withRSA");
                var signature =  rsa.Signer.Sign(
                    signer,
                    content,
                    PrivateKeyFactory.CreateKey(_signingKey));
                writer.Write(signature.Length);
                writer.Write(signature);

                // Writing content.
                writer.Write(content);
                return stream.ToArray();
            }
        }
    }
}
