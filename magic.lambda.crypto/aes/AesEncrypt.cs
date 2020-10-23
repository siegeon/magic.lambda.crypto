﻿/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.IO;
using System.Text;
using System.Linq;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using magic.node;
using magic.node.extensions;
using magic.signals.contracts;

namespace magic.lambda.crypto.aes
{
    /// <summary>
    /// [crypto.aes.encrypt] slot to encrypt some content using a symmetric cryptography algorithm (AES).
    /// </summary>
    [Slot(Name = "crypto.aes.encrypt")]
    public class AesEncrypt : ISlot
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
            var password = rawPassword is string strPwd ? Utilities.Generate256BitKey(strPwd) : rawPassword as byte[];
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;
            input.Clear();

            // Performing actual encryption.
            var result = Utilities.AesEncrypt(password, message);

            // Returning results to caller according to specifications.
            input.Value = raw ? (object)result : Convert.ToBase64String(result);
        }
    }
}
