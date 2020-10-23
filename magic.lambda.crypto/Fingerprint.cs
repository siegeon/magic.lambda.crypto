/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System.Linq;
using magic.node;
using magic.node.extensions;
using magic.signals.contracts;
using magic.lambda.crypto.utilities;

namespace magic.lambda.crypto
{
    /// <summary>
    /// [crypto.fingerprint] slot that returns the fingerprint of whatever it is given.
    /// </summary>
    [Slot(Name = "crypto.fingerprint")]
    public class Fingerprint : ISlot
    {
        public void Signal(ISignaler signaler, Node input)
        {
            // Retrieving arguments.
            var content = Utilities.GetContent(input, true);
            var raw = input.Children.FirstOrDefault(x => x.Name == "raw")?.GetEx<bool>() ?? false;

            // Retrieving fingerprint.
            input.Value = Utilities.CreateFingerprint(content);
        }
    }
}
