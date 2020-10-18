
# Magic Lambda Crypto

Provides cryptographic services to Magic. More specifically, this project provides the following slots, that
among other things helps you with storing passwords securely in your database, in addition to other services,
such as generating cryptographically secured random strings of text, cryptographically signing messages,
verifying signatures, creating encryption keypairs, etc.

* __[crypto.hash]__ - Creates a hash of the specified string value/expression's value, using the specified **[algorithm]**, that defaults to SHA256
* __[crypto.password.hash]__ - Creates a cryptographically secure hash from the specified password, expected to be found in its value node. Uses blowfish, or more specifically BCrypt internally, to create the hash with individual salts.
* __[crypto.password.verify]__ - Verifies a **[hash]** argument matches towards the password specified in its value. The **[hash]** is expected to be in the format created by BCrypt, implying the hash was created with e.g. **[crypto.password.hash]**.
* __[crypto.random]__ - Creates a cryptographically secured random string for you, with the characters [a-zA-Z], '_' and '-'
* __[crypto.rsa.create-key]__ - Creates an RSA keypair for you, allowing you to pass in **[strength]**, and/or **[seed]** to override the default strength being 2048, and apply a custom seed to the random number generator. The private/public keypair will be returned to caller as **[public]** and **[private]** after invocation, which is the DER encoded keys, base64 encoded. Might require a lot of time to execute, depending upon your strength argument's value.
* __[crypto.rsa.sign]__ - Cryptographically signs a message (provided as value) with the given private **[key]**, optionally using the specified hashing **[algorithm]**, defaulting to SHA256, and returns the signature for your content as value. The signature content will be returned as the base64 encoded raw bytes being your signature.
* __[crypto.rsa.verify]__ - Verifies a previously created RSA signature towards its message (provided as value), with the specified public **[key]**, optionally allowing the caller to provide a hashing **[algorithm]**, defaulting to SHA256. The slot will throw an exception if the signature is not matching the message passed in for security reasons.
* __[crypto.rsa.encrypt]__ - Encrypts the specified message (provided as value) using the specified public **[key]**, and returns the encrypted message as a base64 encoded encrypted message. Assumes the data to encrypt is text/string.
* __[crypto.rsa.decrypt]__ - Decrypts the specified message (provided as value) using the specified private **[key]**, and returns the decrypted message as its original plain text value. Assumes the encrypted message was base64 encoded, and the original message was some sort of text/string and not binary content.
* __[crypto.fingerprint]__ - Creates a fingerprint of a piece of text.

## Supported hashing algorithms

All slots above requiring an **[algorithm]** argument, can use these hashing algorithms by default.

* SHA1
* SHA256
* SHA384
* SHA512
* MD5

## [crypto.random]

The **[crypto.random]** can optionally take a **[min]** and **[max]** argument, which defines the min/max length of the
string returned. If not supplied, the default values for these arguments are respectively 10 and 20. This slot is useful
for creating random secrets, and similar types of random strings, where you need cryptographically secured random strings.
An example of generating a cryptographically secure random string of text, between 50 and 100 characters in lenght,
can be found below.

```
crypto.random
   min:50
   max:100
```

Notice, the **[crypto.random]** slot will _only_ return characters from a-z, A-Z, 0-9, \_ and -. Which makes
it easily traversed using any string library.

## Cryptography

This library supports several cryptographic services, allowing you to use the cryptography services you wish.
But first a bit of cryptography theory. Public key cryptography, or what's often referred
to as _"asymmetric cryptography"_ is based upon a *key pair*. One of your keys are intended for being
publicly released, and is often referred to as _"your public key"_. This key can do two important things.

1. It can encrypt data such that *only* its private counterpart key can decrypt the data
2. It can verify that a message originated from a party that has access to its private counterpart

Hence, keeping your *private* key as just that, implying **private**, is of outmost importance. And securely
delivering your public key to the other party, is of equal importance, to make sure they're using the *correct*
public key in their communication with you. If you can keep your private key private,
and securely deliver your public key to others, you have a 100% secure channel to use for communication,
preventing malicious individuals from both reading what others send to you, and also tampering with the
content you send to others, before the other party receives it. Hence, cryptography is about two main subjects.

1. Encrypting messages others send to *you*
2. Allowing you to provide guarantees that a message originated from *you*

Both of these concepts is 100% dependent upon your ability to keep your private key *private* though.
In addition, it relies upon an ability to distribute your public key, such that those wanting to communicate
with you have *that exact public key*. Depending upon your paranoia level, you might just send your
public key in an email, or you might need to physically meet the person whom you want to communicate with,
and give him a USB stick with your public key. The latter might be important if you fear what's often
referred to as a _"man in the middle attack"_, where some malicious agent, takes your public key,
and gives a bogus and fake public key to the other party. This results in that the man in the middle
can intercept your communication, decrypt it, and re-encrypt it with your public key, before he or she
sends it to you - In addition to that he can use a similar mechanism to impersonate your signatures,
allowing the other party to falsely believe some message originated from you, when it did indeed originate
from a malicious _"man in the middle"_.

There are several different ways to create a key pair, just have the above in mind as you start using
cryptography in your Hyperlambda applications. Most of the cryptography functions in this library is
using Bouncy Castle, which is a thoroughly tested library for doing cryptography. Bouncy Castle is
owned by a foundation originating from Australia, so they don't need to obey by American laws, reducing
American intelligence services ability to lawfully force them to build backdoors and similar constructs
into their code. Bouncy Castle is also Open Source, allowing others to scrutinise their code for such
backdoors. However, with cryptography, there *are no guarantees*, only a _"general feeling and concent"_
amongst developers that it's secure.

### Creating an RSA keypair

To create an RSA keypair that you can use for other cryptographic services later, you can use something as follows.

```
crypto.rsa.create-key
   strength:2048
   seed:some random jibberish text
```

Both the **[strength]** and **[seed]** is optional above. Strength will default to 2048, which might be too little
for serious cryptography, but increasing your strength too much, might result in the function spending several
seconds, possibly minutes to return if you set it too high. The **[seed]** is optional, and even if you don't provide
a seed argument, the default seed should still be strong enough to avoid predictions. Internally all of these slots uses
Bouncy Castle.

A good strength for an RSA key, is considered to be 4096, which developers around the world feels are secure enough
to avoid brute force _"guessing"_ of your private key. If you're *very* paranoid, you might want to increase it to
8192, in addition to providing a manual salt as you create your keys. If you're just playing around with cryptography
to learn the ideas, 1024 is probably more than enough.

Notice, if you want the key back as raw bytes, you can supply a **[raw]** argument, and set its value to boolean
true, at which point the returned key(s) will only be DER encoded, and returned as a raw `byte[]`. This might be
useful, if you for instance need to persist the key to disc, as a binary file, etc.

### Cryptographically signing and verifying the signature of a message

You can use a previously created private RSA key to cryptographically sign some data or message, intended to be passed
over an insecure context, allowing the caller to use your public key to verify the message was in fact created
by the owner of the private key. To sign some arbitrary content using your private key, and also verify the message
was correctly signed with a specific key, you can use something as follows.

```
.data:some piece of text you wish to sign

crypto.rsa.create-key

crypto.rsa.sign:x:@.data
   key:x:@crypto.rsa.create-key/*/private

// Uncommenting these lines, will make the verify process throw an exception
// set-value:x:@.data
//    .:Some piece of text you wish to sign - XXXX

crypto.rsa.verify:x:@.data
   signature:x:@crypto.rsa.sign
   key:x:@crypto.rsa.create-key/*/public
```

If somebody tampers with the content between the signing process and the verify process, an exception will
be thrown during the verify stage. Something you can verify yourself by uncommenting the above **[set-value]**
invocation. Throwing an exception is a conscious choice, due to the potential security breaches an error
in your code might have, creating a false positive if you erronously invert an **[if]** statement. Even though
this is technically _"using exceptions for control flow"_, it has been an explicit and conscious design choice
as the library was created, to avoid false positives during the verification process of a signature.

### Encrypting and decrypting a message

To encrypt a message, you can use something as follows.

```
.data:some piece of text you wish to encrypt

crypto.rsa.create-key

crypto.rsa.encrypt:x:@.data
   key:x:@crypto.rsa.create-key/*/public

crypto.rsa.decrypt:x:@crypto.rsa.encrypt
   key:x:@crypto.rsa.create-key/*/private
```

Notice how the encryption above is using the *public key*, and the decryption is using the *private key*. The encrypt slot
will internally base64 encode the encrypted data for simplicity reasons, allowing you to immediately inspect it as text,
since encryption will result in a byte array, which is inconvenient to handle and easily pass around to others.
Hence, the above decrypt slot assumes that it's given the encrypted data as base64 encoded text, and will fail if not.

Also notice how the encrypted message is larger than its original string. This is because of something called _"padding"_
in encryption, only being relevant for messages that are smaller in size than your original text. Padding
implies that no encrypted text resulting of en encryption operation can be significantly smaller in size than the
size of the (public) key used to encrypt the message. This is only relevant for small pieces of data, and have
few implications for larger pieces of text being encrypted.

## Cryptography concerns

Even assuming you can 100% perfectly communicate in privacy today, your privacy is only as good as a malicious
agent's ability to brute force prime numbers, in the case of RSA, and similar techniques with Elliptic Curve.
This means that even though you create an extremely strong keypair according to today's standard - Due to
Moore's law, some 5-10 years down the road, the NSA and the CIA will probably be able to reproduce your private
key, using nothing but your public key as input. And some 10-20 years later, some kid with a pocket calculator,
will also easily do the same. Since these agencies also happens to vacum clean the internet, for everything
transmitted through your ISP, this implies that 5-10 years from now, they'll be able to read your communication,
and figure out what you were talking about some 5-10 years ago.

Also, as quantum computing becomes practical to implement, today's cryptography based upon _"hard problems"_,
will effectively prove useless towards a serious quantum computer's ability to perform multiple math
operations simultaneously, allowing a malicious agent to reproduce your private key in milliseconds.
So far, we don't know about such quantum computers, but it is assumed they will become available in the
not too distant future for organisations with very deep pockets.

This implies that privacy is like fruit and vegetables, it rots over time. If you can live with this,
you can eliminate most of its concerns, by making sure you periodically create stronger and stronger keypairs,
with higher and higher bit strength. However, in the case quantum computing should somehow be practical,
even such strategies are futile for traditional cryptography, such as EC and RSA. If these are no concerns
of you, you can still use cryptography to have a _"practical form of privacy"_ in your communication,
but have this in mind as you start out using cryptography, since there are no certainties when it comes
to this subject. And of course, even if you had access to 100% perfect privacy in your communication with
others, you still need to trust the ones you're communicating with to not tell others about what you
are communicating to them ...

### Torture based decryption

In addition to the above concerns, any shmuck with a baseball bat could probably _"decrypt"_ your
private communication, by simply coercing and torturing the other party to spill the beans. Inevitably,
at some point, everybody breaks. Although there exist ways to counter this too, by for instance start
lying immediately once the torture begins - At which point as the torture victim breaks, he's lied
so much, that it becomes impossible for the torturer to believe anything that his victim says - This is
probably the simplest way of _"decryption"_ that exists, and is easily within the means of any gorilla
having high enough IQ to open a door.

Hence, there is no true privacy, only shades of privacy. This is true regardless of how strong encryption
you are using. Hence ...

> The only true privacy that exists, is never telling anybody anything!

## Quality gates

- [![Build status](https://travis-ci.com/polterguy/magic.lambda.crypto.svg?master)](https://travis-ci.com/polterguy/magic.lambda.crypto)
- [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=polterguy_magic.lambda.crypto&metric=alert_status)](https://sonarcloud.io/dashboard?id=polterguy_magic.lambda.crypto)
- [![Bugs](https://sonarcloud.io/api/project_badges/measure?project=polterguy_magic.lambda.crypto&metric=bugs)](https://sonarcloud.io/dashboard?id=polterguy_magic.lambda.crypto)
- [![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=polterguy_magic.lambda.crypto&metric=code_smells)](https://sonarcloud.io/dashboard?id=polterguy_magic.lambda.crypto)
- [![Coverage](https://sonarcloud.io/api/project_badges/measure?project=polterguy_magic.lambda.crypto&metric=coverage)](https://sonarcloud.io/dashboard?id=polterguy_magic.lambda.crypto)
- [![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=polterguy_magic.lambda.crypto&metric=duplicated_lines_density)](https://sonarcloud.io/dashboard?id=polterguy_magic.lambda.crypto)
- [![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=polterguy_magic.lambda.crypto&metric=ncloc)](https://sonarcloud.io/dashboard?id=polterguy_magic.lambda.crypto)
- [![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=polterguy_magic.lambda.crypto&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=polterguy_magic.lambda.crypto)
- [![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=polterguy_magic.lambda.crypto&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=polterguy_magic.lambda.crypto)
- [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=polterguy_magic.lambda.crypto&metric=security_rating)](https://sonarcloud.io/dashboard?id=polterguy_magic.lambda.crypto)
- [![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=polterguy_magic.lambda.crypto&metric=sqale_index)](https://sonarcloud.io/dashboard?id=polterguy_magic.lambda.crypto)
- [![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=polterguy_magic.lambda.crypto&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=polterguy_magic.lambda.crypto)
