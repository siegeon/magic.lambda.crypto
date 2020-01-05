/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using magic.node.extensions;
using System.Linq;
using Xunit;

namespace magic.lambda.crypto.tests
{
    public class CryptoTests
    {
        [Fact]
        public void VerifyHashCorrectPassword()
        {
            var lambda = Common.Evaluate(@"crypto.password.hash:foo
crypto.password.verify:foo
   hash:x:@crypto.password.hash");
            Assert.Equal(true, lambda.Children.Skip(1).First().Value);
        }

        [Fact]
        public void VerifyHashWrongPassword()
        {
            var lambda = Common.Evaluate(@"crypto.password.hash:foo
crypto.password.verify:WRONG
   hash:x:@crypto.password.hash");
            Assert.Equal(false, lambda.Children.Skip(1).First().Value);
        }

        [Fact]
        public void HashDefaultAlgo()
        {
            var lambda = Common.Evaluate(@"crypto.hash:some-input-string");
            Assert.Equal(
                "D70BEB83530DC0C965FE075C57EB706572A05D5D3D3E117C45FE8236900E80DD",
                lambda.Children.First().Get<string>().ToUpperInvariant());
        }

        [Fact]
        public void HashSha256()
        {
            var lambda = Common.Evaluate(@"crypto.hash:some-input-string
   algorithm:SHA256");
            Assert.Equal(
                "D70BEB83530DC0C965FE075C57EB706572A05D5D3D3E117C45FE8236900E80DD",
                lambda.Children.First().Get<string>().ToUpperInvariant());

            // Asserting hash is lowers.
            Assert.NotEqual(
                "D70BEB83530DC0C965FE075C57EB706572A05D5D3D3E117C45FE8236900E80DD",
                lambda.Children.First().Get<string>());
        }

        [Fact]
        public void HashSha512()
        {
            var lambda = Common.Evaluate(@"crypto.hash:some-input-string
   algorithm:SHA512");
            Assert.Equal(
                "BED2004780419D966327DA73A98BE04CB474AA36C92FD8AF970E49EA9AA05C5F68938E486E20326059CB0290472DEFFD03939C18CAC9364F29C69105CD4130D3",
                lambda.Children.First().Get<string>().ToUpperInvariant());
        }
    }
}
