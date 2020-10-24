/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Text;
using System.Linq;
using magic.node;
using magic.node.extensions;
using magic.signals.contracts;
using magic.lambda.crypto.aes;
using ut = magic.lambda.crypto.utilities;

namespace magic.lambda.crypto.slots.aes
{
    /// <summary>
    /// [crypto.aes.encrypt] slot to encrypt some content using a symmetric cryptography algorithm (AES).
    /// </summary>
    [Slot(Name = "crypto.aes.encrypt")]
    public class Encrypt : ISlot
    {
        /// <summary>
        /// Implementation of slot.
        /// </summary>
        /// <param name="signaler">Signaler invoking slot.</param>
        /// <param name="input">Arguments to slot.</param>
        public void Signal(ISignaler signaler, Node input)
        {
            // Retrieving arguments.
            var rawMessage = input.GetEx<object>();
            var message = rawMessage is string strMsg ? Encoding.UTF8.GetBytes(strMsg) : rawMessage as byte[];
            var rawPassword = input.Children.FirstOrDefault(x => x.Name == "password")?.GetEx<object>() ??
                throw new ArgumentException("No [password] provided to [crypto.aes.encrypt]");
            var password = rawPassword is string strPwd ? ut.Utilities.Generate256BitKey(strPwd) : rawPassword as byte[];
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;
            input.Clear();

            // Performing actual encryption.
            var result = Encrypter.Encrypt(password, message);

            // Returning results to caller according to specifications.
            input.Value = raw ? (object)result : Convert.ToBase64String(result);
        }
    }
}
