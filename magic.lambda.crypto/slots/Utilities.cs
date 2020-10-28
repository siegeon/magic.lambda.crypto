﻿/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Text;
using System.Linq;
using System.Security.Cryptography;
using magic.node;
using magic.node.extensions;

namespace magic.lambda.crypto.slots
{
    /*
     * Helper class to retrieve common arguments.
     */
    internal static class Utilities
    {
        /*
         * Retrieves arguments specified to slot.
         */
        internal static (byte[] Message, byte[] Key, bool Raw) GetArguments(
            Node input,
            bool messageIsBase64,
            string keyName)
        {
            // Retrieving message as byte[], converting if necessary.
            var message = GetContent(input, messageIsBase64);

            // Retrieving key to use for cryptography operation.
            var key = GetKeyFromArguments(input, keyName);

            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;

            input.Clear();
            return (message, key, raw);
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
