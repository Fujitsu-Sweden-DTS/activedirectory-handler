"use strict";
module.exports = {
  env: {
    browser: true,
    commonjs: true,
    es2021: true,
  },
  extends: "eslint:recommended",
  parserOptions: {
    ecmaVersion: 12,
  },
  rules: {
    "array-callback-return": "error",
    "block-scoped-var": "error",
    "consistent-return": "error",
    "constructor-super": "error",
    curly: "error",
    "default-case": "error",
    "default-case-last": "error",
    "default-param-last": "error",
    "dot-notation": "error",
    eqeqeq: "error",
    "init-declarations": ["error", "always"],
    "no-console": "error",
    "no-duplicate-imports": "error",
    "no-empty-function": "error",
    "no-eval": "error",
    "no-extend-native": "error",
    "no-extra-label": "error",
    "no-floating-decimal": "error",
    "no-implicit-globals": "error",
    "no-implied-eval": "error",
    "no-invalid-this": "error",
    "no-iterator": "error",
    "no-label-var": "error",
    "no-lone-blocks": "error",
    "no-lonely-if": "error",
    "no-loop-func": "error",
    "no-loss-of-precision": "error",
    "no-nonoctal-decimal-escape": "error",
    "no-octal-escape": "error",
    "no-promise-executor-return": "error",
    "no-prototype-builtins": "error",
    "no-return-assign": "error",
    "no-self-compare": "error",
    "no-sequences": "error",
    "no-shadow": "error",
    "no-template-curly-in-string": "error",
    "no-throw-literal": "error",
    "no-undef-init": "error",
    "no-undefined": "error",
    "no-unmodified-loop-condition": "error",
    "no-unreachable-loop": "error",
    "no-unsafe-optional-chaining": "error",
    "no-unused-expressions": "error",
    "no-use-before-define": "error",
    "no-useless-backreference": "error",
    "no-useless-call": "error",
    "no-useless-computed-key": "error",
    "no-useless-concat": "error",
    "no-useless-return": "error",
    "no-void": "error",
    "prefer-promise-reject-errors": "error",
    "prefer-regex-literals": "error",
    "prefer-rest-params": "error",
    "prefer-spread": "error",
    "require-atomic-updates": "error",
    "require-await": "error",
    "require-unicode-regexp": "error",
    strict: "error",
    "vars-on-top": "error",
  },
};
