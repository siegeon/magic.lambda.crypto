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
    internal class Decrypter
    {
        readonly AsymmetricKeyParameter _key;

        internal Decrypter(byte[] key)
        {
            _key = PrivateKeyFactory.CreateKey(key);
        }

        /*
         * Decrypts the specified message accordint to the specified arguments.
         */
        internal byte[] Decrypt(byte[] message)
        {
            // Creating our encryption engine, and decorating according to caller's specifications.
            var encryptEngine = new Pkcs1Encoding(new RsaEngine());
            encryptEngine.Init(false, _key);

            // Decrypting message, and returning results to according to caller's specifications.
            var result = encryptEngine.ProcessBlock(message, 0, message.Length);
            return result;
        }
    }
}
