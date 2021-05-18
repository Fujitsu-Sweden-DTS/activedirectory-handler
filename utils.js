"use strict";
const _ = require("lodash");
const assert = require("assert");
const utils = module.exports;

// Make it easier to pass meta-data in an error.
// Use like so: throw utils.err("Error message", {metadata1: value1, otherthing2: value2})
utils.err = function (message, obj) {
  assert(_.isString(message), "First parameter to utils.err must be a string.");
  assert(_.isPlainObject(obj), "Second parameter to utils.err must be a plain object.");
  // Create a new Error object without any message.
  const err = Error("");
  // Add a message.
  err.message = message;
  // Adjust the stack to look like the error was created at the point where utils.err was called.
  // Since the original stack string was created with an empty error message, we know that it takes only 1 line.
  // So, by removing the top 2 lines and adding back a line with the error message, we get the effect of removing the stack frame for the call to utils.err.
  err.stack = [`Error: ${message}`, ...err.stack.split("\n").slice(2)].join("\n");
  // Add other parameters to the error
  for (let key in obj) {
    err[key] = obj[key];
  }
  return err;
};
