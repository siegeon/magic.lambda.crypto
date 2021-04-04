/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2021, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Linq;
using magic.node;
using magic.node.extensions;
using ut = magic.crypto.utilities;

namespace magic.lambda.crypto.slots.aes
{
    /*
     * Helper class to retrieve common arguments.
     */
    internal static class Utilities
    {
        /*
         * Retrieves arguments specified to slot.
         */
        internal static (byte[] Message, byte[] Password, bool Raw) GetArguments(
            Node input,
            bool messageIsBase64)
        {
            // Retrieving message as byte[], converting if necessary.
            var message = slots.Utilities.GetContent(input, messageIsBase64);

            // Retrieving password as byte[], creating SHA256 out of it, if it's a string.
            var rawPassword = input.Children.FirstOrDefault(x => x.Name == "password")?.GetEx<object>() ??
                throw new ArgumentException("No [password] provided to [crypto.aes.xxx]");
            var password = rawPassword is string strPwd ?
                ut.Utilities.Generate256BitKey(strPwd) :
                rawPassword as byte[];

            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;

            input.Clear();
            return (message, password, raw);
        }
    }
}
