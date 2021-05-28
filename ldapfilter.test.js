"use strict";
/* global describe, test, expect */
/* eslint no-magic-numbers: "off" */
const _ = require("lodash");
const assert = require("assert");
const ldapfilter = require("./ldapfilter.js");
const ldapjs = require("ldapjs");

const booleanAttributes = new Set(["boolAttrib1", "boolAttrib2"]);
function iter(n, fun, arg) {
  for (; 0 < n; n--) {
    arg = fun(arg);
  }
  return arg;
}

describe("Test that erroneous ldap filter expressions won't be accepted", () => {
  const test_erroneous_ldap_filters = [
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
    ["true", "anything"], // true has no operands
    ["false", "anything"], // false has no operands
    ["equals", "boolAttrib1", "true"], // illegal value for boolean attribute
    ["equals", "boolAttrib2", "false"], // illegal value for boolean attribute
    ["equals", "boolAttrib1", "TRUEst"], // illegal value for boolean attribute
    ["equals", "boolAttrib2", true], // illegal value for boolean attribute
    ["equals", "boolAttrib1", false], // illegal value for boolean attribute
    ["beginswith", "boolAttrib2", "TRUE"], // illegal operator for boolean attribute
    ["endswith", "boolAttrib1", "FALSE"], // illegal operator for boolean attribute
    ["contains", "boolAttrib2", "TRUE"], // illegal operator for boolean attribute
    ["equals", "_abc", "def"], // underscore is illegal in attribute name
  ];
  for (const bad of test_erroneous_ldap_filters) {
    test(JSON.stringify(bad), () => {
      expect(() => ldapfilter(bad, booleanAttributes)).toThrow();
    });
  }
  test("booleanAttributes required", () => {
    expect(() => ldapfilter(["true"])).toThrow();
    expect(() => ldapfilter(["true"], "string")).toThrow();
  });
});

describe("Test that ldap filter expressions are correctly synthesized", () => {
  const test_cases = [
    {
      //
      str: "(&(cn=lkj\\2a\\28)(cn=lkj\\2a\\28*))",
      exp: ["and", ["equals", "cn", "lkj*("], ["beginswith", "cn", "lkj*("]],
      obj: new ldapjs.AndFilter({ filters: [new ldapjs.EqualityFilter({ attribute: "cn", value: "lkj*(" }), new ldapjs.SubstringFilter({ attribute: "cn", initial: "lkj*(" })] }),
    },
    {
      //
      str: '(|(!(name=*Qwer*))(&(&(cn=*)(&(displayName=*Qwer\\29\\28 /"*)(&(name=_A*)(givenName=*P.\\29))))(!(uid=*))))',
      exp: [
        "or",
        ["not", ["contains", "name", "Qwer"]],
        ["and", ["and", ["has", "cn"], ["and", ["contains", "displayName", 'Qwer)( /"'], ["and", ["beginswith", "name", "_A"], ["endswith", "givenName", "P.)"]]]], ["not", ["has", "uid"]]],
      ],
      obj: new ldapjs.OrFilter({
        filters: [
          new ldapjs.NotFilter({ filter: new ldapjs.SubstringFilter({ attribute: "name", any: ["Qwer"] }) }),
          new ldapjs.AndFilter({
            filters: [
              new ldapjs.AndFilter({
                filters: [
                  new ldapjs.PresenceFilter({ attribute: "cn" }),
                  new ldapjs.AndFilter({
                    filters: [
                      new ldapjs.SubstringFilter({ attribute: "displayName", any: ['Qwer)( /"'] }),
                      new ldapjs.AndFilter({ filters: [new ldapjs.SubstringFilter({ attribute: "name", initial: "_A" }), new ldapjs.SubstringFilter({ attribute: "givenName", final: "P.)" })] }),
                    ],
                  }),
                ],
              }),
              new ldapjs.NotFilter({ filter: new ldapjs.PresenceFilter({ attribute: "uid" }) }),
            ],
          }),
        ],
      }),
    },
    {
      //
      str: "(name=[]{}<>\\28\\29=\\2a\\00\\5cÅÄÖåäö)",
      exp: ["equals", "name", "[]{}<>()=*\u0000\\ÅÄÖåäö"],
      obj: new ldapjs.EqualityFilter({ attribute: "name", value: "[]{}<>()=*\u0000\\ÅÄÖåäö" }),
    },
    {
      //
      str: "(!(objectClass=*))",
      exp: ["oneof", "abc", []],
      obj: new ldapjs.NotFilter({ filter: new ldapjs.PresenceFilter({ attribute: "objectClass" }) }),
    },
    {
      //
      str: "(abc=def)",
      exp: ["oneof", "abc", ["def"]],
      obj: new ldapjs.EqualityFilter({ attribute: "abc", value: "def" }),
    },
    {
      //
      str: "(|(abc=def)(abc=ghi\\28))",
      exp: ["oneof", "abc", ["def", "ghi("]],
      obj: new ldapjs.OrFilter({ filters: [new ldapjs.EqualityFilter({ attribute: "abc", value: "def" }), new ldapjs.EqualityFilter({ attribute: "abc", value: "ghi(" })] }),
    },
    {
      //
      str: "(|(abc=def\\29)(abc=ghi)(abc=jkl))",
      exp: ["oneof", "abc", ["def)", "ghi", "jkl"]],
      obj: new ldapjs.OrFilter({
        filters: [
          new ldapjs.EqualityFilter({ attribute: "abc", value: "def)" }),
          new ldapjs.EqualityFilter({ attribute: "abc", value: "ghi" }),
          new ldapjs.EqualityFilter({ attribute: "abc", value: "jkl" }),
        ],
      }),
    },
    {
      //
      str: "(&(aa=bb)(cc=dd)(ee=ff))",
      exp: ["and", ["equals", "aa", "bb"], ["equals", "cc", "dd"], ["equals", "ee", "ff"]],
      obj: new ldapjs.AndFilter({
        filters: [
          new ldapjs.EqualityFilter({ attribute: "aa", value: "bb" }),
          new ldapjs.EqualityFilter({ attribute: "cc", value: "dd" }),
          new ldapjs.EqualityFilter({ attribute: "ee", value: "ff" }),
        ],
      }),
    },
    {
      //
      str: "(|(aa=bb)(cc=dd)(ee=ff))",
      exp: ["or", ["equals", "aa", "bb"], ["equals", "cc", "dd"], ["equals", "ee", "ff"]],
      obj: new ldapjs.OrFilter({
        filters: [
          new ldapjs.EqualityFilter({ attribute: "aa", value: "bb" }),
          new ldapjs.EqualityFilter({ attribute: "cc", value: "dd" }),
          new ldapjs.EqualityFilter({ attribute: "ee", value: "ff" }),
        ],
      }),
    },
    {
      //
      str: "(cn=abc)",
      exp: ["and", ["equals", "cn", "abc"]],
      obj: new ldapjs.EqualityFilter({ attribute: "cn", value: "abc" }),
    },
    {
      //
      str: "(cn=abc)",
      exp: ["or", ["equals", "cn", "abc"]],
      obj: new ldapjs.EqualityFilter({ attribute: "cn", value: "abc" }),
    },
    {
      //
      str: "(abcDef1=abc)",
      exp: ["equals", "abcDef1", "abc"],
      obj: new ldapjs.EqualityFilter({ attribute: "abcDef1", value: "abc" }),
    },
    {
      //
      str: "(aa=aa)",
      exp: ["and", ["equals", "aa", "aa"]],
      obj: new ldapjs.EqualityFilter({ attribute: "aa", value: "aa" }),
    },
    {
      //
      str: "(&(aa=aa)(aa=bb))",
      exp: ["and", ["equals", "aa", "aa"], ["equals", "aa", "bb"]],
      obj: new ldapjs.AndFilter({ filters: [new ldapjs.EqualityFilter({ attribute: "aa", value: "aa" }), new ldapjs.EqualityFilter({ attribute: "aa", value: "bb" })] }),
    },
    {
      //
      str: "(&(aa=aa)(aa=bb)(aa=cc))",
      exp: ["and", ["equals", "aa", "aa"], ["equals", "aa", "bb"], ["equals", "aa", "cc"]],
      obj: new ldapjs.AndFilter({
        filters: [
          new ldapjs.EqualityFilter({ attribute: "aa", value: "aa" }),
          new ldapjs.EqualityFilter({ attribute: "aa", value: "bb" }),
          new ldapjs.EqualityFilter({ attribute: "aa", value: "cc" }),
        ],
      }),
    },
    {
      //
      str: "(&(aa=aa)(aa=bb)(aa=cc)(aa=dd))",
      exp: ["and", ["equals", "aa", "aa"], ["equals", "aa", "bb"], ["equals", "aa", "cc"], ["equals", "aa", "dd"]],
      obj: new ldapjs.AndFilter({
        filters: [
          new ldapjs.EqualityFilter({ attribute: "aa", value: "aa" }),
          new ldapjs.EqualityFilter({ attribute: "aa", value: "bb" }),
          new ldapjs.EqualityFilter({ attribute: "aa", value: "cc" }),
          new ldapjs.EqualityFilter({ attribute: "aa", value: "dd" }),
        ],
      }),
    },
    {
      //
      str: "(aa=aa)",
      exp: ["or", ["equals", "aa", "aa"]],
      obj: new ldapjs.EqualityFilter({ attribute: "aa", value: "aa" }),
    },
    {
      //
      str: "(|(aa=aa)(aa=bb))",
      exp: ["or", ["equals", "aa", "aa"], ["equals", "aa", "bb"]],
      obj: new ldapjs.OrFilter({ filters: [new ldapjs.EqualityFilter({ attribute: "aa", value: "aa" }), new ldapjs.EqualityFilter({ attribute: "aa", value: "bb" })] }),
    },
    {
      //
      str: "(|(aa=aa)(aa=bb)(aa=cc))",
      exp: ["or", ["equals", "aa", "aa"], ["equals", "aa", "bb"], ["equals", "aa", "cc"]],
      obj: new ldapjs.OrFilter({
        filters: [
          new ldapjs.EqualityFilter({ attribute: "aa", value: "aa" }),
          new ldapjs.EqualityFilter({ attribute: "aa", value: "bb" }),
          new ldapjs.EqualityFilter({ attribute: "aa", value: "cc" }),
        ],
      }),
    },
    {
      //
      str: "(|(aa=aa)(aa=bb)(aa=cc)(aa=dd))",
      exp: ["or", ["equals", "aa", "aa"], ["equals", "aa", "bb"], ["equals", "aa", "cc"], ["equals", "aa", "dd"]],
      obj: new ldapjs.OrFilter({
        filters: [
          new ldapjs.EqualityFilter({ attribute: "aa", value: "aa" }),
          new ldapjs.EqualityFilter({ attribute: "aa", value: "bb" }),
          new ldapjs.EqualityFilter({ attribute: "aa", value: "cc" }),
          new ldapjs.EqualityFilter({ attribute: "aa", value: "dd" }),
        ],
      }),
    },
    {
      //
      str: "(msds-Something=abc)",
      exp: ["equals", "msds-Something", "abc"],
      obj: new ldapjs.EqualityFilter({ attribute: "msds-Something", value: "abc" }),
    },
    {
      //
      str: "(msExchMobileRemoteDocumentsInternalDomainSuffixList=abc)",
      exp: ["equals", "msExchMobileRemoteDocumentsInternalDomainSuffixList", "abc"],
      obj: new ldapjs.EqualityFilter({ attribute: "msExchMobileRemoteDocumentsInternalDomainSuffixList", value: "abc" }),
    },
    {
      //
      str: "(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=abc)",
      exp: ["equals", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "abc"],
      obj: new ldapjs.EqualityFilter({ attribute: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", value: "abc" }),
    },
    {
      //
      str: "(objectClass=*)",
      exp: ["true"],
      obj: new ldapjs.PresenceFilter({ attribute: "objectClass" }),
    },
    {
      //
      str: "(!(objectClass=*))",
      exp: ["false"],
      obj: new ldapjs.NotFilter({ filter: new ldapjs.PresenceFilter({ attribute: "objectClass" }) }),
    },
    {
      //
      str: "(&(member:1.2.840.113556.1.4.1941:=userDN)(|(memberOf:1.2.840.113556.1.4.1941:=groupDN1)(memberOf:1.2.840.113556.1.4.1941:=groupDN2)))",
      exp: ["and", ["equals", "_transitive_member", "userDN"], ["oneof", "_transitive_memberOf", ["groupDN1", "groupDN2"]]],
      obj: new ldapjs.AndFilter({
        filters: [
          new ldapjs.EqualityFilter({ attribute: "member:1.2.840.113556.1.4.1941:", value: "userDN" }),
          new ldapjs.OrFilter({
            filters: [
              new ldapjs.EqualityFilter({ attribute: "memberOf:1.2.840.113556.1.4.1941:", value: "groupDN1" }),
              new ldapjs.EqualityFilter({ attribute: "memberOf:1.2.840.113556.1.4.1941:", value: "groupDN2" }),
            ],
          }),
        ],
      }),
    },
    // Test that ldapfilter does not cause stack overflow
    {
      //
      str: `(|${iter(14, x => `${x}${x}`, "(ab=cd)")})`,
      exp: ["oneof", "ab", iter(2 ** 14, x => ["cd", ...x], [])],
      obj: new ldapjs.OrFilter({ filters: iter(2 ** 14, x => [...x, new ldapjs.EqualityFilter({ attribute: "ab", value: "cd" })], []) }),
    },
    {
      //
      str: `(|${iter(14, x => `${x}${x}`, "(ab=cd)")})`,
      exp: iter(2 ** 14, x => [...x, ["equals", "ab", "cd"]], ["or"]),
      obj: new ldapjs.OrFilter({ filters: iter(2 ** 14, x => [...x, new ldapjs.EqualityFilter({ attribute: "ab", value: "cd" })], []) }),
    },
    {
      //
      str: `(&${iter(14, x => `${x}${x}`, "(ab=cd)")})`,
      exp: iter(2 ** 14, x => [...x, ["equals", "ab", "cd"]], ["and"]),
      obj: new ldapjs.AndFilter({ filters: iter(2 ** 14, x => [...x, new ldapjs.EqualityFilter({ attribute: "ab", value: "cd" })], []) }),
    },
    {
      //
      str: "(&(boolAttrib1=TRUE)(boolAttrib2=FALSE))",
      exp: ["and", ["equals", "boolAttrib1", "TRUE"], ["equals", "boolAttrib2", "FALSE"]],
      obj: new ldapjs.AndFilter({ filters: [new ldapjs.EqualityFilter({ attribute: "boolAttrib1", value: "TRUE" }), new ldapjs.EqualityFilter({ attribute: "boolAttrib2", value: "FALSE" })] }),
    },
  ];
  for (const [index, test_case] of test_cases.entries()) {
    assert(_.isEqual(_.omit(test_case, ["str", "exp", "obj"]), {}));
    assert("str" in test_case);
    assert("exp" in test_case);
    assert("obj" in test_case);
    test(`${index}`, () => {
      const { str: expected_filterstring, exp: filterexpression, obj: ldapjs_filterobject } = test_case;
      const filterexpression_clone = _.cloneDeep(filterexpression);
      const actual_filterstring = ldapfilter(filterexpression, booleanAttributes);
      const ldapjs_filterstring = ldapjs_filterobject.toString();
      expect(actual_filterstring).toBe(expected_filterstring); // Test that ldapfilter synthesizes correctly
      expect(filterexpression).toEqual(filterexpression_clone); // Test that ldapfilter does not alter its argument
      expect(ldapjs_filterstring).toBe(expected_filterstring); // Use ldapjs to double-check that ldapfilter synthesizes correctly
    });
  }
});
