# activedirectory-handler

## What is it

A library for fetching data from Active Directory.

## Why another LDAP library

We couldn't find an existing one that matched our needs.
It is implemented as a wrapper around [ldapjs](http://ldapjs.org/).
Compared to ldapjs, this package have the following advantages:

* Exposes result set as an asynchronous generator with back-pressure, meaning you can consume the search result using `for await` as slowly as needed and with limited memory use.
* Protects against injection into filter expressions by forcing use of a DSL rather than filter strings.
* Handles single- and multi-valued attributes correctly.
  Values come in an array if and only if the attribute is multi-valued.
* Correctly parses several data types that ldapjs doesn't:
  Sid, GUID, Bool, Int32, Windows NT time format, GeneralizedTime and OctetString.
* Workaround for a server refusing to return all entries in the `member` attribute.

and the following disadvantages:

* It is strictly for searching. No server functionality, and no client functionality for adding, deleting or modifying data.
* Less performant at first call. This is due to an initialization routine that reads the entire AD schema.
* Probably slightly less performant in general due to being implemented as a wrapper.

## How to use it

Import and configure it like so:
```js
const ActiveDirectoryHandler = require("@fujitsusweden/activedirectory-handler");
const adHandler = new ActiveDirectoryHandler({
  url: "ldap://your-domain.example.com",
  user: "username",
  password: "password",
  domainBaseDN: "ou=MainOU,dc=your-domain,dc=example,dc=com",
  schemaConfigBaseDN: "cn=Schema,cn=Configuration,dc=your-domain,dc=example,dc=com",
  log,
  isSingleValued: {
    exampleAttribute: true,
  },
});
```

Details for configuration options:

* `domainBaseDN` will be used as the default value for the `from` option in searches, see below.
* `log` is an object holding the following log functions: `debug`, `info`, `warn`, `error` and `critical`.
  Each log function should be an async function taking arguments `data` and `req`.
* `isSingleValued`: Attributes will be treated as single- or multi-valued depending on their schema.
  This optional parameter can be used to override schema information.
  If `exampleAttribute` is declared in the AD schema as multi-valued but no entity has more than one such value and you don't want to deal with an array, you can force treating it as single-valued as in the example above.

Search example:

```js
for await (const user of adHandler.getObjects({
  select: ["distinguishedName", "sn"],
  from: "ou=Users,ou=MainOU,dc=your-domain,dc=example,dc=com",
  where: ["and", ["equals", "objectCategory", "person"], ["equals", "objectClass", "user"]],
  req,
})) {
  console.log(user)
}
```

Details for options to `getObjects`:

* `select` is an array of the attribute names to fetch.
* `from` is the base DN to search. Defaults to `domainBaseDN` given to `new ActiveDirectoryHandler`.
* `where` is a filter expression. See 'LDAP filter DSL' below.
* `scope` is one of `base`, `one` or `sub`. Defaults to `sub`.
* `req` for passing to the log functions.

If you expect exactly one result entry, you can use `getOneObject` instead of `getObjects`.

### LDAP filter DSL


A filter expression in this [DSL/mini-language](https://en.wikipedia.org/wiki/Domain-specific_language) is made up of strings and arrays.
It has the following grammar:

```
     <expression> := <and> | <or> | <not> | <equals> | <beginswith> | <endswith> | <contains> | <has> | <oneof> | <true> | <false>
     <and>        := ["and", <expression>, <expression>, ...]
     <or>         := ["or", <expression>, <expression>, ...]
     <not>        := ["not", <expression>]
     <equals>     := ["equals", <attribute>, <value>]
     <beginswith> := ["beginswith", <attribute>, <value>]
     <endswith>   := ["endswith", <attribute>, <value>]
     <contains>   := ["contains", <attribute>, <value>]
     <has>        := ["has", <attribute>]
     <oneof>      := ["oneof", <attribute>, <arrValue>]
     <true>       := ["true"]
     <false>      := ["false"]
     <attribute>  := A string matching /^[a-z][A-Za-z0-9-]{1,59}$/ i.e. 1-60 English alphanumeric characters or dashes, the first of which is a lower-case letter
     <value>      := A string matching /^.{1,255}$/ i.e. with a length in the interval [1, 255]
     <arrValue>   := An array with zero or more items, each of which a <value>
```

The semantics are as follows:

```
     ["and", X1, ...]:     All expressions are true (given at least 1).
     ["or", X1, ...]:      At least one expression is true (given at least 1).
     ["not", X]:           X is false
     ["equals", A, V]:     True if the object has an attribute A with a value that equals V, or a multi-valued attribute A where at least one of the values equals V.
     ["beginswith", A, V]: True if the object has an attribute A with a value that begins with V, or a multi-valued attribute A where at least one of the values begins with V.
     ["endswith", A, V]:   True if the object has an attribute A with a value that ends with V, or a multi-valued attribute A where at least one of the values ends with V.
     ["contains", A, V]:   True if the object has an attribute A with a value that contains V as a substring, or a multi-valued attribute A where at least one of the values contains V as a substring.
     ["has", A]:           True if the object has an attribute A with any value.
     ["oneof", A, arrV]:   True if the object has an attribute A with a value that equals at least one of the elements of arrV, or a multi-valued attribute A where at least one of the values equals at least one of the elements of arrV.
     ["true"]:             Always true.
     ["false"]:            Always false.
```

Note that the expressions `beginswith`, `endswith` and `contains`, cannot be used with DN attributes. See details [here](https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx)

## Development

Run `./script` without arguments for help
