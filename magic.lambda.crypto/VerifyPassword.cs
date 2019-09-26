/*
 * Magic, Copyright(c) Thomas Hansen 2019 - thomas@gaiasoul.com
 * Licensed as Affero GPL unless an explicitly proprietary license has been obtained.
 */

using System;
using System.Linq;
using bc = BCrypt.Net;
using magic.node;
using magic.node.extensions;
using magic.signals.contracts;

namespace magic.lambda.crypto
{
    [Slot(Name = "crypto.password.verify")]
    public class VerifyPassword : ISlot
    {
        public void Signal(ISignaler signaler, Node input)
        {
            var hash = input.Children.FirstOrDefault(x => x.Name == "hash")?.GetEx<string>();
            if (hash == null)
                throw new ApplicationException($"No [hash] value provided to [crypto.password.verify]");

            var value = input.GetEx<string>();

            input.Value = bc.BCrypt.Verify(value, hash);
        }
    }
}
