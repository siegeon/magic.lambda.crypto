
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
But first a bit of cryptography theory might be in its place. Public key cryptography, or what's often referred
to as _"asymmetric cryptography"_ is based upon a *key pair*. One of your keys are intended for being
publicly released, and is often referred to as _"your public key"_. This key can do two important things.

1. It can encrypt data such that *only* its private counterpart key can decrypt the data
2. It can verify that a message originated from a part that has access to its private counterpart

Hence, keeping your *private* key as just that, implying **private** is of outmost importance. If you can
keep your private key private, and also securely distribute your public key to others wanting to encrypt
messages sent to you, such that only you can read it, and they can verify that some message originated from you -
You have a 100% secure channel to use for communication, preventing malicious individuals from both reading
what others send to you, and also tampering with the content you send to others, before the other party
receives it. Hence, cryptography is about two main subjects.

1. Encrypting messages sent to *you*
2. Allowing you to provide guarantees that a message originated from *you*

Both of these concepts is 100% dependent upon your ability to keep your private key *private* though.
There are several different ways to create a key pair, just have the above in mind as you do, and you
start using cryptography in your Hyperlambda applications.

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

### Cryptographically signing and verifying a message

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
   key:x:@crypto.rsa.create-key/*/public
```

If somebody tampers with the content between the signing process and the verify process, an exception will
be thrown during the verify stage. Something you can verify yourself by uncommenting the above **[set-value]**
invocation.

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
