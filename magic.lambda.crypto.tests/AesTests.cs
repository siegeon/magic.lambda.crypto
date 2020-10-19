/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Linq;
using Xunit;

namespace magic.lambda.crypto.tests
{
    public class AesTests
    {
        [Fact]
        public void EncryptDecrypt128bits()
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
   password:abcdefghij123456abcdefghij123456
crypto.aes.decrypt:x:-
   strength:256
   password:abcdefghij123456abcdefghij123456
");
            Assert.NotEqual("Howdy, this is cool", lambda.Children.First().Value);
            Assert.Equal("Howdy, this is cool", lambda.Children.Skip(1).First().Value);
        }

        [Fact]
        public void EncryptDecrypt_Throws()
        {
            Assert.Throws<ArgumentException>(() => Common.Evaluate(@"
crypto.aes.encrypt:Howdy, this is cool
   strength:256
"));
        }

        [Fact]
        public void EncryptDecryptDefaultBits()
        {
            var lambda = Common.Evaluate(@"
crypto.aes.encrypt:Howdy, this is cool
   password:abcdefghij123456abcdefghij123456
crypto.aes.decrypt:x:-
   password:abcdefghij123456abcdefghij123456
");
            Assert.NotEqual("Howdy, this is cool", lambda.Children.First().Value);
            Assert.Equal("Howdy, this is cool", lambda.Children.Skip(1).First().Value);
        }
    }
}
