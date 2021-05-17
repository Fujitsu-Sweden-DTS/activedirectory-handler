"use strict";
const _ = require("lodash");
const assert = require("assert");

// The following function is gratefully stolen from lib/helpers.js in the
// package ldap-filter.
/**
 * RFC 2254 Escaping of filter strings
 *
 * Raw                     Escaped
 * (o=Parens (R Us))       (o=Parens \28R Us\29)
 * (cn=star*)              (cn=star\2A)
 * (filename=C:\MyFile)    (filename=C:\5cMyFile)
 *
 * @author [Austin King](https://github.com/ozten)
 */
function _escape(inp) {
  if (typeof inp === "string") {
    let esc = "";
    for (let i = 0; i < inp.length; i++) {
      switch (inp[i]) {
        case "*":
          esc += "\\2a";
          break;
        case "(":
          esc += "\\28";
          break;
        case ")":
          esc += "\\29";
          break;
        case "\\":
          esc += "\\5c";
          break;
        case "\0":
          esc += "\\00";
          break;
        default:
          esc += inp[i];
          break;
      }
    }
    return esc;
  } else {
    return inp;
  }
}

// An LDAP Filter synthesizer. The purpose is to avoid injection vulnerabilities
// and other bugs related to escaping.
// @return: The LDAP filter as a string
// @arg i:
//     A filter expression, made up of strings and arrays, with the following
//     grammar:
//
//     <expression> := <and> | <or> | <not> | <equals> | <beginswith> |
//                     <endswith> | <contains> | <has> | <oneof>
//     <and>        := ["and", <expression>, <expression>, ...]
//     <or>         := ["or", <expression>, <expression>, ...]
//     <not>        := ["not", <expression>]
//     <equals>     := ["equals", <attribute>, <value>]
//     <beginswith> := ["beginswith", <attribute>, <value>]
//     <endswith>   := ["endswith", <attribute>, <value>]
//     <contains>   := ["contains", <attribute>, <value>]
//     <has>        := ["has", <attribute>]
//     <oneof>      := ["oneof", <attribute>, <arrValue>]
//     <attribute>  := A string matching /^[a-z][A-Za-z0-9-]{1,59}$/ i.e. 1-60
//                     English alphanumeric characters or dashes, the first of
//                     which is a lower-case letter.
//     <value>      := A string matching /^.{1,255}$/ i.e. with a length in the
//                     interval [1, 255]
//     <arrValue>   := An array with zero or more items, each of which a <value>
//
//     The filter expression has the following semantics:
//
//     ["and", X1, ...]:     All expressions are true (given at least 1).
//     ["or", X1, ...]:      At least one expression is true (given at least 1).
//     ["not", X]:           X is false
//     ["equals", A, V]:     True if the object has an attribute A with a value
//                           that equals V, or a multi-valued attribute A where
//                           at least one of the values equals V.
//     ["beginswith", A, V]: True if the object has an attribute A with a value
//                           that begins with V, or a multi-valued attribute A
//                           where at least one of the values begins with V.
//     ["endswith", A, V]:   True if the object has an attribute A with a value
//                           that ends with V, or a multi-valued attribute A
//                           where at least one of the values ends with V.
//     ["contains", A, V]:   True if the object has an attribute A with a value
//                           that contains V as a substring, or a multi-valued
//                           attribute A where at least one of the values
//                           contains V as a substring.
//     ["has", A]:           True if the object has an attribute A with any
//                           value.
//     ["oneof", A, arrV]:   True if the object has an attribute A with a value
//                           that equals at least one of the elements of arrV,
//                           or a multi-valued attribute A where at least one of
//                           the values equals at least one of the elements of
//                           arrV.
//
// Note that the expressions beginswith, endswith and contains, cannot be used
// with DN attributes. See:
// https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx

// Synthesize <attribute>
function synthattribute(a) {
  assert(typeof a === "string");
  assert(a.match(/^[a-z][A-Za-z0-9-]{1,59}$/u));
  return a;
}
// Synthesize <value>
function synthvalue(a) {
  assert(typeof a === "string");
  assert(a.match(/^.{1,255}$/u));
  return _escape(a);
}
// Synthesize <expression>
function ldapfilter(i) {
  assert(Array.isArray(i));
  let l = i.length;
  assert(l > 0);
  let op = i[0];
  assert(typeof op === "string");
  switch (op) {
    case "and":
    case "or":
      // The '&' and '|' syntax allows any number of operands >= 1, but let's use it only with at least 2.
      assert(l >= 2);
      if (l === 2) {
        return ldapfilter(i[1]);
      }
      return "(" + { and: "&", or: "|" }[op] + _.map(_.slice(i, 1), ldapfilter).join("") + ")";
    case "not":
      assert(l === 2);
      return "(!" + ldapfilter(i[1]) + ")";
    case "equals":
      assert(l === 3);
      return "(" + synthattribute(i[1]) + "=" + synthvalue(i[2]) + ")";
    case "beginswith":
      assert(l === 3);
      return "(" + synthattribute(i[1]) + "=" + synthvalue(i[2]) + "*)";
    case "endswith":
      assert(l === 3);
      return "(" + synthattribute(i[1]) + "=*" + synthvalue(i[2]) + ")";
    case "contains":
      assert(l === 3);
      return "(" + synthattribute(i[1]) + "=*" + synthvalue(i[2]) + "*)";
    case "has":
      assert(l === 2);
      return "(" + synthattribute(i[1]) + "=*)";
    case "oneof":
      assert(l === 3);
      {
        let attribute = i[1];
        let arrValue = i[2];
        assert(_.isArray(arrValue));
        if (arrValue.length === 0) {
          // We're asked to match at least one of zero possibilities.
          // This means matching no objects.
          return ldapfilter(["has", "thisisnotanattributethatshouldexist"]);
        }
        // if arrValue has at least one element:
        return ldapfilter(["or", ..._.map(arrValue, val => ["equals", attribute, val])]);
      }
    default:
      throw Error("Error in LDAP filter expression");
  }
}

module.exports = ldapfilter;
