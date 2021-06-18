/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2021, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System.Text;
using magic.node;
using magic.crypto.aes;
using magic.signals.contracts;

namespace magic.lambda.crypto.slots.aes
{
    /// <summary>
    /// [crypto.aes.decrypt] slot to decrypt some content using a symmetric cryptography algorithm (AES),
    /// that was previously encrypted using the same algorithm.
    /// </summary>
    [Slot(Name = "crypto.aes.decrypt")]
    public class Decrypt : ISlot
    {
        /// <summary>
        /// Implementation of slot.
        /// </summary>
        /// <param name="signaler">Signaler invoking slot.</param>
        /// <param name="input">Arguments to slot.</param>
        public void Signal(ISignaler signaler, Node input)
        {
            // Retrieving arguments.
            var arguments = Utilities.GetArguments(input, true);

            // Performing actual decryption.
            var decrypter = new Decrypter(arguments.Password);
            var result = decrypter.Decrypt(arguments.Message);

            // Returning results to caller according to specifications.
            input.Value = arguments.Raw ? (object)result : Encoding.UTF8.GetString(result);
        }
    }
}
