"use strict";
/* global describe, test, expect */
const _ = require("lodash");
const assert = require("assert");
const ldapfilter = require("./ldapfilter.js");

function iter(n, fun, arg) {
  while (n) {
    arg = fun(arg);
    n--;
  }
  return arg;
}

describe("Test that erroneous ldap filter expressions won't be accepted", () => {
  var test_erroneous_ldap_filters = [
    ["and"], // Operator 'and' must have at least one arguments
    ["or"], // Operator 'or' must have at least one arguments
    ["equals", "Abc", "def"], // Attributes cannot begin with capital letter
    ["equals", "", "def"], // Attributes must not be empty
    ["equals", "abc", ""], // Values must not be empty
    ["equals", ["a"], "def"], // Attributes must be strings
    ["equals", 123, "def"], // Attributes must be strings
    ["equals", "abc", ["a"]], // Values must be strings
    ["equals", "abc", 123], // Values must be strings
    ["equals", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "def"], // Attributes must be no longer than 60 characters
    ["equals", "a", "aa"], // Attributes must be at least 2 characters
    ["equals", "abcåäö", "aa"], // Attributes must not contain non-English letters
    ["not", ["equals", "aa", "aa"], ["equals", "aa", "aa"]], // Operator 'not' must have exactly one argument
    ["not"], // Operator 'not' must have exactly one argument
    ["not", "string"], // Argument to operator 'not' must be an expression
    ["not", 123], // Argument to operator 'not' must be an expression
    ["and", ["equals", "aa", "aa"], "string"], // Arguments to operator 'and' must be an expression
    ["oneof", "abc", "def"], // arrValue must be an array
    ["oneof", "abc", 123], // arrValue must be an array
    ["oneof", "abc", [["abc"]]], // arrValue elements must be valid values
    ["oneof", "abc", [123]], // arrValue elements must be valid values
  ];
  for (let bad of test_erroneous_ldap_filters) {
    test(JSON.stringify(bad), () => {
      expect(() => ldapfilter(bad)).toThrow();
    });
  }
});

describe("Test that ldap filter expressions are correctly synthesized", () => {
  const test_cases = [
    {
      //
      str: "(&(cn=lkj\\2a\\28)(cn=lkj\\2a\\28*))",
      exp: ["and", ["equals", "cn", "lkj*("], ["beginswith", "cn", "lkj*("]],
    },
    {
      //
      str: '(|(!(name=*Qwer*))(&(&(cn=*)(&(displayName=*Qwer\\29\\28 /"*)(&(name=_A*)(givenName=*P.\\29))))(!(uid=*))))',
      exp: [
        "or",
        ["not", ["contains", "name", "Qwer"]],
        ["and", ["and", ["has", "cn"], ["and", ["contains", "displayName", 'Qwer)( /"'], ["and", ["beginswith", "name", "_A"], ["endswith", "givenName", "P.)"]]]], ["not", ["has", "uid"]]],
      ],
    },
    {
      //
      str: "(name=[]{}<>\\28\\29=\\2a\\00\\5cÅÄÖåäö)",
      exp: ["equals", "name", "[]{}<>()=*\u0000\\ÅÄÖåäö"],
    },
    {
      //
      str: "(thisisnotanattributethatshouldexist=*)",
      exp: ["oneof", "abc", []],
    },
    {
      //
      str: "(abc=def)",
      exp: ["oneof", "abc", ["def"]],
    },
    {
      //
      str: "(|(abc=def)(abc=ghi\\28))",
      exp: ["oneof", "abc", ["def", "ghi("]],
    },
    {
      //
      str: "(|(abc=def\\29)(abc=ghi)(abc=jkl))",
      exp: ["oneof", "abc", ["def)", "ghi", "jkl"]],
    },
    {
      //
      str: "(&(aa=bb)(cc=dd)(ee=ff))",
      exp: ["and", ["equals", "aa", "bb"], ["equals", "cc", "dd"], ["equals", "ee", "ff"]],
    },
    {
      //
      str: "(|(aa=bb)(cc=dd)(ee=ff))",
      exp: ["or", ["equals", "aa", "bb"], ["equals", "cc", "dd"], ["equals", "ee", "ff"]],
    },
    {
      //
      str: "(cn=abc)",
      exp: ["and", ["equals", "cn", "abc"]],
    },
    {
      //
      str: "(cn=abc)",
      exp: ["or", ["equals", "cn", "abc"]],
    },
    {
      //
      str: "(abcDef1=abc)",
      exp: ["equals", "abcDef1", "abc"],
    },
    {
      //
      str: "(aa=aa)",
      exp: ["and", ["equals", "aa", "aa"]],
    },
    {
      //
      str: "(&(aa=aa)(aa=bb))",
      exp: ["and", ["equals", "aa", "aa"], ["equals", "aa", "bb"]],
    },
    {
      //
      str: "(&(aa=aa)(aa=bb)(aa=cc))",
      exp: ["and", ["equals", "aa", "aa"], ["equals", "aa", "bb"], ["equals", "aa", "cc"]],
    },
    {
      //
      str: "(&(aa=aa)(aa=bb)(aa=cc)(aa=dd))",
      exp: ["and", ["equals", "aa", "aa"], ["equals", "aa", "bb"], ["equals", "aa", "cc"], ["equals", "aa", "dd"]],
    },
    {
      //
      str: "(aa=aa)",
      exp: ["or", ["equals", "aa", "aa"]],
    },
    {
      //
      str: "(|(aa=aa)(aa=bb))",
      exp: ["or", ["equals", "aa", "aa"], ["equals", "aa", "bb"]],
    },
    {
      //
      str: "(|(aa=aa)(aa=bb)(aa=cc))",
      exp: ["or", ["equals", "aa", "aa"], ["equals", "aa", "bb"], ["equals", "aa", "cc"]],
    },
    {
      //
      str: "(|(aa=aa)(aa=bb)(aa=cc)(aa=dd))",
      exp: ["or", ["equals", "aa", "aa"], ["equals", "aa", "bb"], ["equals", "aa", "cc"], ["equals", "aa", "dd"]],
    },
    {
      //
      str: "(msds-Something=abc)",
      exp: ["equals", "msds-Something", "abc"],
    },
    {
      //
      str: "(msExchMobileRemoteDocumentsInternalDomainSuffixList=abc)",
      exp: ["equals", "msExchMobileRemoteDocumentsInternalDomainSuffixList", "abc"],
    },
    {
      //
      str: "(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=abc)",
      exp: ["equals", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "abc"],
    },
    // Test that ldapfilter does not cause stack overflow
    {
      //
      str: "(|" + iter(14, x => `${x}${x}`, "(ab=cd)") + ")",
      exp: ["oneof", "ab", iter(2 ** 14, x => ["cd", ...x], [])],
    },
    {
      //
      str: "(|" + iter(14, x => `${x}${x}`, "(ab=cd)") + ")",
      exp: iter(2 ** 14, x => [...x, ["equals", "ab", "cd"]], ["or"]),
    },
    {
      //
      str: "(&" + iter(14, x => `${x}${x}`, "(ab=cd)") + ")",
      exp: iter(2 ** 14, x => [...x, ["equals", "ab", "cd"]], ["and"]),
    },
  ];
  for (const [index, test_case] of test_cases.entries()) {
    assert(_.isEqual(_.omit(test_case, ["str", "exp"]), {}));
    test("" + index, () => {
      const { str: expected_filterstring, exp: filterexpression } = test_case;
      const filterexpression_clone = _.cloneDeep(filterexpression);
      const actual_filterstring = ldapfilter(filterexpression);
      expect(actual_filterstring).toBe(expected_filterstring); // Test that ldapfilter synthesizes correctly
      expect(filterexpression).toEqual(filterexpression_clone); // Test that ldapfilter does not alter its argument
    });
  }
});
