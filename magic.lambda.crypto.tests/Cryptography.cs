/*
 * Magic, Copyright(c) Thomas Hansen 2019 - 2020, thomas@servergardens.com, all rights reserved.
 * See the enclosed LICENSE file for details.
 */

using System.Linq;
using Xunit;

namespace magic.lambda.crypto.tests
{
    public class Cryptography
    {
        [Fact]
        public void SignAndEncrypt()
        {
            var lambda = Common.Evaluate(@"

// Recipient's key(s)
crypto.rsa.create-key
   strength:1024

// Sender's key(s).
crypto.rsa.create-key
   strength:1024

// Fingerprint of key used to sign content.
crypto.hash:x:@crypto.rsa.create-key/*/public
   format:raw

crypto.sign-and-encrypt:This is some super secret!
   encryption-key:x:@crypto.rsa.create-key/@crypto.rsa.create-key/*/public
   signing-key:x:@crypto.rsa.create-key/*/private
   signing-key-fingerprint:x:@crypto.hash
");
            var msg = lambda.Children.Skip(3).First().Value as string;
            Assert.NotNull(msg);
            Assert.True(msg.Length > 500 && msg.Length < 700);
        }

        [Fact]
        public void SignAndEncrypt_Raw()
        {
            var lambda = Common.Evaluate(@"

// Recipient's key(s)
crypto.rsa.create-key
   strength:1024
   raw:true

// Sender's key(s).
crypto.rsa.create-key
   strength:1024
   raw:true

// Fingerprint of key used to sign content.
crypto.hash:x:@crypto.rsa.create-key/*/public
   format:raw

crypto.sign-and-encrypt:This is some super secret!
   encryption-key:x:@crypto.rsa.create-key/@crypto.rsa.create-key/*/public
   signing-key:x:@crypto.rsa.create-key/*/private
   signing-key-fingerprint:x:@crypto.hash
   raw:true
");
            var msg = lambda.Children.Skip(3).First().Value as byte[];
            Assert.NotNull(msg);
            Assert.True(msg.Length > 300 && msg.Length < 500);
        }

        [Fact]
        public void SignEncryptDecryptAndVerify()
        {
            var lambda = Common.Evaluate(@"

// Receiver's key(s).
crypto.rsa.create-key
   strength:1024

// Sender's key(s).
crypto.rsa.create-key
   strength:1024

// Fingerprint of key used to sign content.
crypto.hash:x:@crypto.rsa.create-key/*/public
   format:raw

// Signing and encrypting.
crypto.sign-and-encrypt:This is some super secret!
   encryption-key:x:@crypto.rsa.create-key/@crypto.rsa.create-key/*/public
   signing-key:x:@crypto.rsa.create-key/*/private
   signing-key-fingerprint:x:@crypto.hash
   raw:true

// Decrypting and verifying signature.
crypto.decrypt-and-verify:x:-
   decryption-key:x:@crypto.rsa.create-key/@crypto.rsa.create-key/*/private
");
            var msg = lambda.Children.Skip(4).First().Value as string;
            Assert.Equal("This is some super secret!", msg);
        }
    }
}
