"use strict";
/* eslint no-magic-numbers: ["error", { ignore: [0, 1, 2, 3] }] */
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

// An LDAP Filter synthesizer. The purpose is to avoid injection vulnerabilities and other bugs related to escaping.
// @return: The LDAP filter as a string
// @arg i: A filter expression, made up of strings and arrays. See ./README.md for details.
// @arg b: A set of the names for the attributes to treat as booleans.

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
function ldapfilter(i, b) {
  assert(Array.isArray(i));
  assert(_.isSet(b));
  const l = i.length;
  assert(l > 0);
  const op = i[0];
  assert(typeof op === "string");
  switch (op) {
    case "and":
    case "or":
      // The '&' and '|' syntax allows any number of operands >= 1, but let's use it only with at least 2.
      assert(l >= 2);
      if (l === 2) {
        return ldapfilter(i[1], b);
      }
      return `(${{ and: "&", or: "|" }[op]}${_.map(_.slice(i, 1), x => ldapfilter(x, b)).join("")})`;
    case "not":
      assert(l === 2);
      return `(!${ldapfilter(i[1], b)})`;
    case "equals":
      assert(l === 3);
      if (b.has(i[1])) {
        assert(i[2] === "TRUE" || i[2] === "FALSE", `'${i[1]} is a boolean attribute and can only be equal to 'TRUE' or 'FALSE'.`);
      }
      return `(${synthattribute(i[1])}=${synthvalue(i[2])})`;
    case "beginswith":
      assert(l === 3);
      assert(!b.has(i[1]), `'${i[1]} is a boolean attribute and is not allowed in 'beginswith' expressions.`);
      return `(${synthattribute(i[1])}=${synthvalue(i[2])}*)`;
    case "endswith":
      assert(l === 3);
      assert(!b.has(i[1]), `'${i[1]} is a boolean attribute and is not allowed in 'endswith' expressions.`);
      return `(${synthattribute(i[1])}=*${synthvalue(i[2])})`;
    case "contains":
      assert(l === 3);
      assert(!b.has(i[1]), `'${i[1]} is a boolean attribute and is not allowed in 'contains' expressions.`);
      return `(${synthattribute(i[1])}=*${synthvalue(i[2])}*)`;
    case "has":
      assert(l === 2);
      return `(${synthattribute(i[1])}=*)`;
    case "oneof":
      assert(l === 3);
      {
        const attribute = i[1];
        const arrValue = i[2];
        assert(_.isArray(arrValue));
        if (arrValue.length === 0) {
          // We're asked to match at least one of zero possibilities.
          // This means matching no objects.
          return ldapfilter(["false"], b);
        }
        // if arrValue has at least one element:
        return ldapfilter(["or", ..._.map(arrValue, val => ["equals", attribute, val])], b);
      }
    case "true":
      assert(l === 1);
      return ldapfilter(["has", "objectClass"], b);
    case "false":
      assert(l === 1);
      return ldapfilter(["not", ["true"]], b);
    default:
      throw Error("Error in LDAP filter expression");
  }
}

module.exports = ldapfilter;
