/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Linq;
using System.Text;
using magic.node.extensions;
using Xunit;

namespace magic.lambda.crypto.tests
{
    public class AesTests
    {
        [Fact]
        public void EncryptDecrypt()
        {
            var lambda = Common.Evaluate(@"
crypto.aes.encrypt:Howdy, this is cool
   strength:128
   password:abcdefghij123456
crypto.aes.decrypt:x:-
   strength:128
   password:abcdefghij123456
");
            Assert.NotEqual("Howdy, this is cool", lambda.Children.First().Value);
            Assert.Equal("Howdy, this is cool", lambda.Children.Skip(1).First().Value);
        }

        [Fact]
        public void EncryptDecrypt256bits()
        {
            var lambda = Common.Evaluate(@"
crypto.aes.encrypt:Howdy, this is cool
   strength:256
   password:098765432109876543210987654321qw098765432109876543210987654321qw
crypto.aes.decrypt:x:-
   strength:256
   password:098765432109876543210987654321qw098765432109876543210987654321qw
");
            Assert.NotEqual("Howdy, this is cool", lambda.Children.First().Value);
            Assert.Equal("Howdy, this is cool", lambda.Children.Skip(1).First().Value);
        }
    }
}
