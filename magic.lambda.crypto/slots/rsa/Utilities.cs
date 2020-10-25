/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Text;
using System.Linq;
using magic.node;
using magic.node.extensions;
using ut = magic.lambda.crypto.utilities;

namespace magic.lambda.crypto.slots.rsa
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
            var rawMessage = input.GetEx<object>();
            var message = rawMessage is string strMsg ?
                messageIsBase64 ?
                    Convert.FromBase64String(strMsg) :
                    Encoding.UTF8.GetBytes(strMsg) :
                rawMessage as byte[];

            // Retrieving key to use for cryptography operation.
            var key = ut.Utilities.GetKeyFromArguments(input, keyName);

            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;

            input.Clear();
            return (message, key, raw);
        }
    }
}
