/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using magic.node;
using magic.node.extensions;

namespace magic.lambda.crypto
{
    /*
     * Helper utility class to provide common functions for other classes and methods.
     */
    internal static class Helpers
    {
        /*
         * Returns a public key according to the given arguments.
         */
        internal static AsymmetricKeyParameter GetPublicKey(Node input)
        {
            // Sanity checking invocation.
            var keys = input.Children.Where(x => x.Name == "public-key" || x.Name == "key");
            if (keys.Count() != 1)
                throw new ArgumentException("You must provide exactly one key, either as [public-key] or as [key]");
            
            // Making sure we support both raw keys and base64 encoded keys.
            var key = keys.First()?.GetEx<object>();
            if (key is string strKey)
                return PublicKeyFactory.CreateKey(Convert.FromBase64String(strKey)); // base64

            // Raw byte[] key.
            return PublicKeyFactory.CreateKey(key as byte[]);
        }

        /*
         * Returns a private key according to the given arguments.
         */
        internal static AsymmetricKeyParameter GetPrivateKey(Node input)
        {
            // Sanity checking invocation.
            var keys = input.Children.Where(x => x.Name == "private-key" || x.Name == "key");
            if (keys.Count() != 1)
                throw new ArgumentException("You must provide exactly one key, either as [private-key] or as [key]");
            
            // Making sure we support both raw keys and base64 encoded keys.
            var key = keys.First()?.GetEx<object>();
            if (key is string strKey)
                return PrivateKeyFactory.CreateKey(Convert.FromBase64String(strKey)); // base64

            // Raw byte[] key.
            return PrivateKeyFactory.CreateKey(key as byte[]);
        }
    }
}
