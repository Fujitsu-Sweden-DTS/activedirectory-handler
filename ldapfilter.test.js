"use strict";
/* global describe, test, expect */
const _ = require("lodash");
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

describe("Test that ldap filter expressions are correctly synthesized and that ldapfilter does not alter it's argument", () => {
  var test_synthesized_ldap_filters = [
    "(&(cn=lkj\\2a\\28)(cn=lkj\\2a\\28*))",
    ["and", ["equals", "cn", "lkj*("], ["beginswith", "cn", "lkj*("]],

    '(|(!(name=*Qwer*))(&(&(cn=*)(&(displayName=*Qwer\\29\\28 /"*)(&(name=_A*)(givenName=*P.\\29))))(!(uid=*))))',
    [
      "or",
      ["not", ["contains", "name", "Qwer"]],
      ["and", ["and", ["has", "cn"], ["and", ["contains", "displayName", 'Qwer)( /"'], ["and", ["beginswith", "name", "_A"], ["endswith", "givenName", "P.)"]]]], ["not", ["has", "uid"]]],
    ],

    "(name=[]{}<>\\28\\29=\\2a\\00\\5cÅÄÖåäö)",
    ["equals", "name", "[]{}<>()=*\u0000\\ÅÄÖåäö"],

    "(thisisnotanattributethatshouldexist=*)",
    ["oneof", "abc", []],

    "(abc=def)",
    ["oneof", "abc", ["def"]],

    "(|(abc=def)(abc=ghi\\28))",
    ["oneof", "abc", ["def", "ghi("]],

    "(|(abc=def\\29)(|(abc=ghi)(abc=jkl)))",
    ["oneof", "abc", ["def)", "ghi", "jkl"]],

    "(&(aa=bb)(&(cc=dd)(ee=ff)))",
    ["and", ["equals", "aa", "bb"], ["equals", "cc", "dd"], ["equals", "ee", "ff"]],

    "(|(aa=bb)(|(cc=dd)(ee=ff)))",
    ["or", ["equals", "aa", "bb"], ["equals", "cc", "dd"], ["equals", "ee", "ff"]],

    "(cn=abc)",
    ["and", ["equals", "cn", "abc"]],

    "(cn=abc)",
    ["or", ["equals", "cn", "abc"]],

    "(abcDef1=abc)",
    ["equals", "abcDef1", "abc"],

    "(aa=aa)",
    ["and", ["equals", "aa", "aa"]],

    "(&(aa=aa)(aa=bb))",
    ["and", ["equals", "aa", "aa"], ["equals", "aa", "bb"]],

    "(&(aa=aa)(&(aa=bb)(aa=cc)))",
    ["and", ["equals", "aa", "aa"], ["equals", "aa", "bb"], ["equals", "aa", "cc"]],

    "(&(&(aa=aa)(aa=bb))(&(aa=cc)(aa=dd)))",
    ["and", ["equals", "aa", "aa"], ["equals", "aa", "bb"], ["equals", "aa", "cc"], ["equals", "aa", "dd"]],

    "(aa=aa)",
    ["or", ["equals", "aa", "aa"]],

    "(|(aa=aa)(aa=bb))",
    ["or", ["equals", "aa", "aa"], ["equals", "aa", "bb"]],

    "(|(aa=aa)(|(aa=bb)(aa=cc)))",
    ["or", ["equals", "aa", "aa"], ["equals", "aa", "bb"], ["equals", "aa", "cc"]],

    "(|(|(aa=aa)(aa=bb))(|(aa=cc)(aa=dd)))",
    ["or", ["equals", "aa", "aa"], ["equals", "aa", "bb"], ["equals", "aa", "cc"], ["equals", "aa", "dd"]],

    "(msds-Something=abc)",
    ["equals", "msds-Something", "abc"],

    "(msExchMobileRemoteDocumentsInternalDomainSuffixList=abc)",
    ["equals", "msExchMobileRemoteDocumentsInternalDomainSuffixList", "abc"],

    "(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=abc)",
    ["equals", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "abc"],

    // Test that ldapfilter does not cause stack overflow

    iter(14, x => `(|${x}${x})`, "(ab=cd)"),
    ["oneof", "ab", iter(2 ** 14, x => ["cd", ...x], [])],

    iter(14, x => `(|${x}${x})`, "(ab=cd)"),
    iter(2 ** 14, x => [...x, ["equals", "ab", "cd"]], ["or"]),

    iter(14, x => `(&${x}${x})`, "(ab=cd)"),
    iter(2 ** 14, x => [...x, ["equals", "ab", "cd"]], ["and"]),
  ];
  let tests = _.chunk(test_synthesized_ldap_filters, 2);
  for (let xindex = 0; xindex < tests.length; xindex++) {
    let x = tests[xindex];
    test("" + xindex, () => {
      const [expected_filterstring, filterexpression] = x;
      const filterexpression_clone = _.cloneDeep(filterexpression);
      const actual_filterstring = ldapfilter(filterexpression);
      expect(actual_filterstring).toBe(expected_filterstring);
      expect(filterexpression).toEqual(filterexpression_clone);
    });
  }
});
