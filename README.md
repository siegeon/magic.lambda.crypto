
# Magic Lambda Crypto

[![Build status](https://travis-ci.org/polterguy/magic.lambda.crypto.svg?master)](https://travis-ci.org/polterguy/magic.lambda.crypto)

Provides cryptographic services to [Magic](https://github.com/polterguy/magic). More specifically, it provides two slots, that helps you
with storing passwords secured in your database.

* __[crypto.hash]__ - Creates a hash of the specified string value/expression's value, using the specified **[algorithm]**.
* __[crypto.password.hash]__ - Creates a cryptographically secure hash from the specified password, expected to be found in its value node.
* __[crypto.password.verify]__ - Verifies a **[hash]** argument matches towards the password specified in its value.
* __[crypto.random]__ - Creates a cryptographically secured random string for you, with the characters [a-zA-Z], '_' and '-'.

The above password slots will use BlowFish algorithm, through BCrypt, while the supported algorithms for the **[crypto.hash]**
are as follows.

* SHA1
* SHA256
* SHA384
* SHA512
* MD5

The **[crypto.random]** can optionally take a **[min]** and **[max]** argument, which defines the min/max length of the
string returned. If not supplied, the default values for these arguments are respectively 10 and 20.

## License

Although most of Magic's source code is publicly available, Magic is _not_ Open Source or Free Software.
You have to obtain a valid license key to install it in production, and I normally charge a fee for such a
key. You can [obtain a license key here](https://servergardens.com/buy/).
Notice, 5 hours after you put Magic into production, it will stop functioning, unless you have a valid
license for it.

* [Get licensed](https://servergardens.com/buy/)
