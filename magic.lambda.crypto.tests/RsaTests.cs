/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Linq;
using magic.node.extensions;
using Xunit;

namespace magic.lambda.crypto.tests
{
    public class RsaTests
    {
        [Fact]
        public void GenerateKey1024()
        {
            var lambda = Common.Evaluate(@"
crypto.rsa.create-key
   strength:1024");
            var privateLength = lambda.Children.First().Children.Skip(1).First().GetEx<string>().Length;
            var publicLength = lambda.Children.First().Children.First().GetEx<string>().Length;
            Assert.True(privateLength > 800 && privateLength < 900);
            Assert.True(publicLength > 180 && publicLength < 250);
        }

        [Fact]
        public void GenerateKey1024ExplicitSeed()
        {
            var lambda = Common.Evaluate(@"
crypto.rsa.create-key
   seed:Thomas Hansen is cool
   strength:1024");
            var privateLength = lambda.Children.First().Children.Skip(1).First().GetEx<string>().Length;
            var publicLength = lambda.Children.First().Children.First().GetEx<string>().Length;
            Assert.True(privateLength > 800 && privateLength < 900);
            Assert.True(publicLength > 180 && publicLength < 250);
        }

        [Fact]
        public void GenerateKey2048()
        {
            var lambda = Common.Evaluate(@"
crypto.rsa.create-key
   strength:2048");
            var privateLength = lambda.Children.First().Children.Skip(1).First().GetEx<string>().Length;
            var publicLength = lambda.Children.First().Children.First().GetEx<string>().Length;
            Assert.True(privateLength > 1550 && privateLength < 1800);
            Assert.True(publicLength > 350 && publicLength < 400);
        }

        [Fact]
        public void GenerateKey1024Twice()
        {
            var lambda = Common.Evaluate(@"
crypto.rsa.create-key
   strength:1024
crypto.rsa.create-key
   strength:1024");
            Assert.NotEqual(
                lambda.Children.First().Children.First().GetEx<string>(),
                lambda.Children.First().Children.Skip(1).First().GetEx<string>());
        }

        [Fact]
        public void SignText()
        {
            var lambda = Common.Evaluate(@"
.data:This is some piece of text that should be signed
crypto.rsa.create-key
   strength:1024
crypto.rsa.sign:x:@.data
   key:x:@crypto.rsa.create-key/*/private");
            Assert.NotNull(lambda.Children.Skip(2).First().GetEx<string>());
            Assert.True(lambda.Children.Skip(2).First().Value.GetType() != typeof(Expression));
            Assert.NotEqual(
                "This is some piece of text that should be signed",
                lambda.Children.Skip(2).First().GetEx<string>());
        }

        [Fact]
        public void SignTextSha512()
        {
            var lambda = Common.Evaluate(@"
.data:This is some piece of text that should be signed
crypto.rsa.create-key
   strength:1024
crypto.rsa.sign:x:@.data
   algorithm:SHA512
   key:x:@crypto.rsa.create-key/*/private");
            Assert.NotNull(lambda.Children.Skip(2).First().GetEx<string>());
            Assert.True(lambda.Children.Skip(2).First().Value.GetType() != typeof(Expression));
            Assert.NotEqual(
                "This is some piece of text that should be signed",
                lambda.Children.Skip(1).First().GetEx<string>());
        }

        [Fact]
        public void SignText_Throws()
        {
            Assert.Throws<ArgumentException>(() => Common.Evaluate(@"
.data:This is some piece of text that should be signed
crypto.rsa.create-key
   strength:1024
crypto.rsa.sign:x:@.data
   key:x:@crypto.rsa.create-key/*/public"));
        }

        [Fact]
        public void SignAndVerifyText()
        {
            Common.Evaluate(@"
.data:This is some piece of text that should be signed
crypto.rsa.create-key
   strength:1024
crypto.rsa.sign:x:@.data
   key:x:@crypto.rsa.create-key/*/private
crypto.rsa.verify:x:@.data
   key:x:@crypto.rsa.create-key/*/public
   signature:x:@crypto.rsa.sign
");
        }

        [Fact]
        public void SignAndVerifyTextSha512()
        {
            Common.Evaluate(@"
.data:This is some piece of text that should be signed
crypto.rsa.create-key
   strength:1024
crypto.rsa.sign:x:@.data
   algorithm:SHA512
   key:x:@crypto.rsa.create-key/*/private
crypto.rsa.verify:x:@.data
   algorithm:SHA512
   key:x:@crypto.rsa.create-key/*/public
   signature:x:@crypto.rsa.sign
");
        }

        [Fact]
        public void SignAndVerifyTextSHA1()
        {
            Common.Evaluate(@"
.data:This is some piece of text that should be signed
crypto.rsa.create-key
   strength:1024
crypto.rsa.sign:x:@.data
   algorithm:SHA1
   key:x:@crypto.rsa.create-key/*/private
crypto.rsa.verify:x:@.data
   algorithm:SHA1
   key:x:@crypto.rsa.create-key/*/public
   signature:x:@crypto.rsa.sign
");
        }

        [Fact]
        public void SignAndVerifyTextSHA384()
        {
            Common.Evaluate(@"
.data:This is some piece of text that should be signed
crypto.rsa.create-key
   strength:1024
crypto.rsa.sign:x:@.data
   algorithm:SHA384
   key:x:@crypto.rsa.create-key/*/private
crypto.rsa.verify:x:@.data
   algorithm:SHA384
   key:x:@crypto.rsa.create-key/*/public
   signature:x:@crypto.rsa.sign
");
        }

        [Fact]
        public void SignAndVerifyTextMD5()
        {
            Common.Evaluate(@"
.data:This is some piece of text that should be signed
crypto.rsa.create-key
   strength:1024
crypto.rsa.sign:x:@.data
   algorithm:MD5
   key:x:@crypto.rsa.create-key/*/private
crypto.rsa.verify:x:@.data
   algorithm:MD5
   key:x:@crypto.rsa.create-key/*/public
   signature:x:@crypto.rsa.sign
");
        }

        [Fact]
        public void SignAndVerifyText_Throws_01()
        {
            Assert.Throws<ArgumentException>(() => Common.Evaluate(@"
.data1:This is some piece of text that should be signed
.data2:ThiS is some piece of text that should be signed
crypto.rsa.create-key
   strength:1024
crypto.rsa.sign:x:@.data1
   key:x:@crypto.rsa.create-key/*/private
crypto.rsa.verify:x:@.data2
   key:x:@crypto.rsa.create-key/*/public
   signature:x:@crypto.rsa.sign
"));
        }

        [Fact]
        public void SignAndVerifyText_Throws_02()
        {
            Assert.Throws<ArgumentException>(() => Common.Evaluate(@"
.data1:This is some piece of text that should be signed
.data2:This is some piece of text that should be signed
crypto.rsa.create-key
   strength:1024
crypto.rsa.sign:x:@.data1
   algorithm:SHA256
   key:x:@crypto.rsa.create-key/*/private
crypto.rsa.verify:x:@.data2
   algorithm:SHA512
   key:x:@crypto.rsa.create-key/*/public
   signature:x:@crypto.rsa.sign
"));
        }

        [Fact]
        public void EncryptText()
        {
            var lambda = Common.Evaluate(@"
.data:This is some piece of text that should be encrypted
crypto.rsa.create-key
   strength:1024
crypto.rsa.encrypt:x:@.data
   key:x:@crypto.rsa.create-key/*/public");
            Assert.NotNull(lambda.Children.Skip(2).First().GetEx<string>());
            Assert.True(lambda.Children.Skip(2).First().Value.GetType() != typeof(Expression));
            System.Console.WriteLine(lambda.ToHyperlambda());
            Assert.NotEqual(
                "This is some piece of text that should be encrypted",
                lambda.Children.Skip(2).First().GetEx<string>());
        }
    }
}
