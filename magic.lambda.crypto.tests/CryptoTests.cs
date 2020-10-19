/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System;
using System.Linq;
using Xunit;
using magic.node.extensions;

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
        public void VerifyHashPasswordThrows()
        {
            Assert.Throws<ArgumentException>(() => Common.Evaluate(@"crypto.password.hash:foo
crypto.password.verify:WRONG"));
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

        [Fact]
        public void HashSha384()
        {
            var lambda = Common.Evaluate(@"crypto.hash:some-input-string
   algorithm:SHA384");
            Assert.Equal(
                "F0DBFDF28BB9DF25715EB129E2270366E3E73FB509AF1E196269450898AA38820D645DE072EF4434AF3A097A693C178B",
                lambda.Children.First().Get<string>().ToUpperInvariant());
        }

        [Fact]
        public void HashShaThrows()
        {
            Assert.Throws<ArgumentException>(() => Common.Evaluate(@"crypto.hash:some-input-string
   algorithm:Non-Existing"));
        }

        [Fact]
        public void RandomCharacters()
        {
            var lambda = Common.Evaluate(@"crypto.random
   min:50
   max:100");
            Assert.NotNull(lambda.Children.First().Value);
            Assert.True(lambda.Children.First().Get<string>().Length >= 50);
            Assert.True(lambda.Children.First().Get<string>().Length <= 100);
        }

        [Fact]
        public void RandomCharacters_DefaultLength()
        {
            var lambda = Common.Evaluate(@"crypto.random");
            Assert.NotNull(lambda.Children.First().Value);
            Assert.True(lambda.Children.First().Get<string>().Length >= 10);
            Assert.True(lambda.Children.First().Get<string>().Length <= 20);
        }
    }
}
