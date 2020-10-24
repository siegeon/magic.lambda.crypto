/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace magic.lambda.crypto.rsa
{
    /*
     * Utility class to provide common functions for other classes and methods.
     */
    internal class Signer
    {
        readonly AsymmetricKeyParameter _key;

        public Signer(byte[] key)
        {
            _key = PrivateKeyFactory.CreateKey(key);
        }

        /*
         * Cryptographically signs the specified message, according to caller's specifications.
         */
        internal byte[] Sign(string algo, byte[] message)
        {
            var signer = SignerUtilities.GetSigner($"{algo}withRSA");
            return Sign(signer, message, _key);
        }

        /*
         * Cryptographically signs the specified message.
         */
        internal static byte[] Sign(
            ISigner signer,
            byte[] message,
            AsymmetricKeyParameter key)
        {
            signer.Init(true, key);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.GenerateSignature();
        }
    }
}
