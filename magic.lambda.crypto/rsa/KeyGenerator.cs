/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using magic.lambda.crypto.utilities;

namespace magic.lambda.crypto.rsa
{
    /*
     * Utility class to create an RSA key pair.
     */
    internal class KeyGenerator
    {
        readonly SecureRandom _csrng;

        public KeyGenerator(byte[] seed)
        {
            _csrng = new SecureRandom();
            if (seed != null)
                _csrng.SetSeed(seed);
        }

        /*
         * Creates a new keypair using the specified key pair generator, and returns the key pair to caller.
         */
        internal (byte[] Private, byte[] Public, string Fingerprint) Generate(int strength)
        {
            var generator = new RsaKeyPairGenerator();
            generator.Init(new KeyGenerationParameters(_csrng, strength));

            // Creating keypair.
            var keyPair = generator.GenerateKeyPair();
            var privateInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
            var publicInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);

            // Returning key pair according to caller's specifications.
            var publicKey = publicInfo.GetDerEncoded();
            var fingerprint = Utilities.CreateFingerprint(publicKey);

            // Returning as DER encoded raw byte[].
            return (privateInfo.GetDerEncoded(), publicKey, fingerprint);
        }
    }
}
