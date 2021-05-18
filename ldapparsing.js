"use strict";
const _ = require("lodash");
const assert = require("assert");
const momentHandler = require("./momentHandler.js");
const utils = require("./utils");

// The 18-digit Active Directory timestamps, also named 'Windows NT time
// format', 'Win32 FILETIME or SYSTEMTIME' or NTFS file time. These are used in
// Microsoft Active Directory for pwdLastSet, accountExpires, LastLogon,
// LastLogonTimestamp, and LastPwdSet. The timestamp is the number of
// 100-nanosecond intervals (1 nanosecond = one billionth of a second) since Jan
// 1, 1601 UTC. (From https://www.epochconverter.com/ldap)
exports.dateFormatter_WinNT = function (WinNT_time) {
  let milliseconds_since_1601 = BigInt(WinNT_time) / 10000n;
  let milliseconds_since_1970 = milliseconds_since_1601 - 11644473600000n;
  return momentHandler.formatDatestring(new Date(Number.parseInt(milliseconds_since_1970.toString())), null, "YYYY-MM-DD HH:mm:ss");
};

exports.dateFormatter_ADGeneralizedTime = function (x) {
  return momentHandler.formatDatestring(x, "YYYYMMDDhhmmss.Z", "YYYY-MM-DD HH:mm:ss");
};

const hex = n => ("0" + n.toString(16)).substr(-2).toUpperCase();

exports.ldapBufferToGuid = function (__ignored, buffer) {
  const b = _.map(buffer, hex);
  return ["{", b[3], b[2], b[1], b[0], "-", b[5], b[4], "-", b[7], b[6], "-", b[8], b[9], "-", ...b.slice(10), "}"].join("");
};

// https://ldapwiki.com/wiki/ObjectSID
exports.ldapBufferToSid = function (__ignored, buffer) {
  let b = _.map(buffer, BigInt);
  let blen = BigInt(b.length);
  assert(8n <= blen);
  let revision = b[0];
  assert(revision === 1n);
  let count = b[1];
  assert(blen === 8n + 4n * count);
  let authority = (b[2] << 40n) | (b[3] << 32n) | (b[4] << 24n) | (b[5] << 16n) | (b[6] << 8n) | b[7];
  let sid = `S-${revision}-${authority}`;
  for (let i = 0; i < count; i++) {
    let offset = 8 + 4 * i;
    let subauthority = b[offset] | (b[offset + 1] << 8n) | (b[offset + 2] << 16n) | (b[offset + 3] << 24n);
    sid = `${sid}-${subauthority}`;
  }
  return sid;
};

exports.ldapBufferToGenericOctetString = function (__ignored, buffer) {
  const b = _.map(buffer, hex);
  return b.join(" ");
};

exports.ldapBool = function (value) {
  if (value === "TRUE") {
    return true;
  }
  if (value === "FALSE") {
    return false;
  }
  throw utils.err("This value does not parse to a boolean", { value });
};

exports.int32 = obj => (typeof obj === "string" ? (obj === "" ? null : Number.parseInt(obj)) : obj);
