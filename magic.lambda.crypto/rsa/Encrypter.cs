/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Encodings;

namespace magic.lambda.crypto.rsa
{
    /*
     * Utility class to provide common functions for other classes and methods.
     */
    internal class Encrypter
    {
        readonly AsymmetricKeyParameter _key;

        public Encrypter(byte[] key)
        {
            _key = PublicKeyFactory.CreateKey(key);
        }

        /*
         * Encrypts the specified message according to the specified arguments.
         */
        internal byte[] Encrypt(byte[] message)
        {
            // Creating our encryption engine, and decorating according to caller's specifications.
            var encryptionEngine = new Pkcs1Encoding(new RsaEngine());
            encryptionEngine.Init(true, _key);

            // Encrypting message, and returning results to according to caller's specifications.
            var result = encryptionEngine.ProcessBlock(message, 0, message.Length);
            return result;
        }
    }
}
