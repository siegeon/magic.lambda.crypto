/*
 * Magic Cloud, copyright Aista, Ltd. See the attached LICENSE file for details.
 */

using magic.node;
using magic.signals.contracts;
using ut = magic.lambda.crypto.lib.utilities;

namespace magic.lambda.crypto.slots.misc
{
    /// <summary>
    /// [crypto.fingerprint] slot that returns the fingerprint of whatever it is given.
    /// </summary>
    [Slot(Name = "crypto.fingerprint")]
    public class Fingerprint : ISlot
    {
        /// <summary>
        /// Implementation of slot.
        /// </summary>
        /// <param name="signaler">Signaler invoking slot.</param>
        /// <param name="input">Arguments to slot.</param>
        public void Signal(ISignaler signaler, Node input)
        {
            // Retrieving arguments.
            var content = Utilities.GetContent(input, true);

            // Retrieving fingerprint.
            input.Value = ut.Utilities.CreateSha256Fingerprint(content);
        }
    }
}
