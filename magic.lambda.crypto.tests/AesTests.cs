/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Linq;
using System.Text;
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
   password:abcdefghij123456
crypto.aes.decrypt:x:-
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
   password:abcdefghij123456abcdefghij123456
crypto.aes.decrypt:x:-
   password:abcdefghij123456abcdefghij123456
");
            Assert.True(lambda.Children.First().Value is string);
            Assert.NotEqual("Howdy, this is cool", lambda.Children.First().Value);
            Assert.Equal("Howdy, this is cool", lambda.Children.Skip(1).First().Value);
        }

        [Fact]
        public void EncryptDecrypt256bits_Raw()
        {
            var lambda = Common.Evaluate(@"
crypto.aes.encrypt:Howdy, this is cool
   password:abcdefghij123456abcdefghij123456
   raw:true
crypto.aes.decrypt:x:-
   password:abcdefghij123456abcdefghij123456
   raw:true
");
            Assert.NotEqual("Howdy, this is cool", lambda.Children.First().Value);
            Assert.True(lambda.Children.First().Value is byte[]);
            Assert.Equal(Encoding.UTF8.GetBytes("Howdy, this is cool"), lambda.Children.Skip(1).First().Value);
        }

        [Fact]
        public void EncryptDecrypt_Throws_01()
        {
            Assert.Throws<ArgumentException>(() => Common.Evaluate(@"
crypto.aes.encrypt:Howdy, this is cool
   password:abcdefghij123456abcdefghij123456
crypto.aes.decrypt:x:-
"));
        }

        [Fact]
        public void EncryptDecrypt_Throws_02()
        {
            Assert.Throws<ArgumentException>(() => Common.Evaluate(@"
crypto.aes.encrypt:Howdy, this is cool
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
