
# Magic Lambda Crypto

[![Build status](https://travis-ci.org/polterguy/magic.lambda.crypto.svg?master)](https://travis-ci.org/polterguy/magic.lambda.crypto)

Provides cryptographic services to [Magic](https://github.com/polterguy/magic). More specifically, it provides two slots, that helps you
with storing passwords secured in your database.

* __[crypto.password.hash]__ - Creates a cryptographically secure hash from the specified password, expected to be found in its value node.
* __[crypto.password.verify]__ - Verifies a [hash] argument matches towards the password specified in its value.

## License

Magic is licensed as Affero GPL. This means that you can only use it to create Open Source solutions.
If this is a problem, you can contact at thomas@gaiasoul.com me to negotiate a proprietary license if
you want to use the framework to build closed source code. This will allow you to use Magic in closed
source projects, in addition to giving you access to Microsoft SQL Server adapters, to _"crudify"_
database tables in MS SQL Server. I also provide professional support for clients that buys a
proprietary enabling license.
