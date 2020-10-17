/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

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
    }
}
