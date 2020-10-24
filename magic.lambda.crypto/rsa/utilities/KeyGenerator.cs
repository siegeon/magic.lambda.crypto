/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using magic.node;
using magic.node.extensions;
using magic.lambda.crypto.utilities;

namespace magic.lambda.crypto.rsa.utilities
{
    /*
     * Utility class to create an RSA key pair.
     */
    internal static class KeyGenerator
    {
        /*
         * Creates a new keypair using the specified key pair generator, and returns the key pair to caller.
         */
        internal static void CreateNewKeyPair(Node input, IAsymmetricCipherKeyPairGenerator generator)
        {
            // Retrieving arguments, if given, or supplying sane defaults if not.
            var strength = input.Children.FirstOrDefault(x => x.Name == "strength")?.GetEx<int>() ?? 2048;
            var seed = input.Children.FirstOrDefault(x => x.Name == "seed")?.GetEx<string>();
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;

            // Clearing existing node, to avoid returning garbage back to caller.
            input.Clear();

            // Initializing our generator according to caller's specifications.
            var rnd = new SecureRandom();
            if (seed != null)
                rnd.SetSeed(Encoding.UTF8.GetBytes(seed));
            generator.Init(new KeyGenerationParameters(rnd, strength));

            // Creating keypair.
            var keyPair = generator.GenerateKeyPair();
            var privateInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
            var publicInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);

            // Returning key pair according to caller's specifications.
            var publicKey = publicInfo.GetDerEncoded();
            var fingerprint = Utilities.CreateFingerprint(publicKey);
            if (raw)
            {
                // Returning as DER encoded raw byte[].
                input.Add(new Node("private", privateInfo.GetDerEncoded()));
                input.Add(new Node("public", publicKey));
                input.Add(new Node("fingerprint", fingerprint));
            }
            else
            {
                // Returning as base64 encoded DER format.
                input.Add(new Node("private", Convert.ToBase64String(privateInfo.GetDerEncoded())));
                input.Add(new Node("public", Convert.ToBase64String(publicKey)));
                input.Add(new Node("fingerprint", fingerprint));
            }
        }
    }
}
