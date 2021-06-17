/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2021, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Text;
using System.Linq;
using Microsoft.Extensions.Configuration;
using magic.node;
using magic.node.extensions;
using magic.signals.contracts;
using magic.crypto.combinations;

namespace magic.lambda.crypto.slots.combinations
{
    /// <summary>
    /// [crypto.encrypt] slot that signs and encrypts the specified
    /// content using the spcified arguments.
    /// 
    /// This slot will first cryptographically sign the message, then encrypt it,
    /// resulting in a format you can read about in the project's README.md file.
    /// </summary>
    [Slot(Name = "crypto.encrypt")]
    public class Encrypt : ISlot
    {
        readonly IConfiguration _configuration;

        /// <summary>
        /// Creates an instance of your slot.
        /// </summary>
        /// <param name="configuration">Needed to retrieve common seed for operation</param>
        public Encrypt(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        /// <summary>
        /// Implementation of slot.
        /// </summary>
        /// <param name="signaler">Signaler invoking slot.</param>
        /// <param name="input">Arguments to slot.</param>
        public void Signal(ISignaler signaler, Node input)
        {
            // Retrieving arguments.
            var arguments = GetArguments(input);

            // Signing content.
            var signer = new Signer(arguments.SigningKey, arguments.SigningKeyFingerprint);
            var signed = signer.Sign(arguments.Content);

            // Encrypting content.
            var encrypter = new Encrypter(arguments.EncryptionKey, arguments.Seed);
            var rawResult = encrypter.Encrypt(signed);

            // Returning results to caller.
            input.Value = arguments.Raw ? (object)rawResult : Convert.ToBase64String(rawResult);
        }

        #region [ -- Private helper methods -- ]

        /*
         * Retrieves arguments for invocation.
         */
        (byte[] Content, byte[] SigningKey, byte[] EncryptionKey, byte[] SigningKeyFingerprint, byte[] Seed, bool Raw) GetArguments(Node input)
        {
            var content = Utilities.GetContent(input);
            var signingKey = Utilities.GetKeyFromArguments(input, "signing-key");
            var encryptionKey = Utilities.GetKeyFromArguments(input, "encryption-key");
            var signingKeyFingerprint = Utilities.GetFingerprint(input);
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;
            var seedRaw = input.Children.FirstOrDefault(x => x.Name == "seed")?.GetEx<object>();

            // Notice, even if caller never supplied a manual seed, we still apply the auth secret as the default seed to create maximum amount of entropy.
            var seed = seedRaw is string strSeed ?
                Encoding.UTF8.GetBytes(strSeed + _configuration["magic:auth:secret"]) :
                (seedRaw as byte[]).Concat(Encoding.UTF8.GetBytes(_configuration["magic:auth:secret"])).ToArray();

            input.Clear();
            return (content, signingKey, encryptionKey, signingKeyFingerprint, seed, raw);
        }

        #endregion
    }
}
