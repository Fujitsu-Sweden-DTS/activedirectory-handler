"use strict";
const _ = require("lodash");
const assert = require("assert");
const ldapfilter = require("./ldapfilter");
const ldapjs = require("ldapjs");
const ldapparsing = require("./ldapparsing");
const futile = require("@fujitsusweden/futile");
const { promisify } = require("util");
const integrationTests = require("./integrationTests.js");

const AttributeNameRE = ldapfilter.AttributeNameRE;
const attributesNeededForInitialization = ["lDAPDisplayName", "attributeSyntax", "isSingleValued"];
const initialize_throttle_delay = 10000;
const buffer_pause_at_length = 2000;
const buffer_resume_at_length = 200;
function validDN(dn) {
  try {
    ldapjs.parseDN(dn);
    return true;
  } catch (e) {
    if (e.name === "InvalidDistinguishedNameError") {
      return false;
    }
    throw e;
  }
}

class ActiveDirectoryHandler {
  constructor(activedirectoryHandlerConfig) {
    const {
      //
      clientSideTransitiveSearchBaseDN,
      clientSideTransitiveSearchDefault,
      domainBaseDN,
      log,
      overrideSingleValued = {},
      password,
      schemaConfigBaseDN,
      url,
      user,
      ...invalidConfigOptions
    } = activedirectoryHandlerConfig;
    assert(
      !("isSingleValued" in activedirectoryHandlerConfig),
      "You included an invalid option `isSingleValued` in the config for ActiveDirectoryHandler. Did you perhaps mean `overrideSingleValued`?",
    );
    assert(_.size(invalidConfigOptions) === 0, `Invalid option(s) in the config for ActiveDirectoryHandler: ${_.keys(invalidConfigOptions)}`);

    // The Base DN for the domain
    assert(validDN(domainBaseDN), "domainBaseDN must be a valid DN");
    this.domainBaseDN = domainBaseDN;

    if (clientSideTransitiveSearchBaseDN) {
      assert(validDN(clientSideTransitiveSearchBaseDN), "clientSideTransitiveSearchBaseDN must be a valid DN");
      this.clientSideTransitiveSearchBaseDN = clientSideTransitiveSearchBaseDN;
    } else {
      this.clientSideTransitiveSearchBaseDN = domainBaseDN;
    }
    assert(_.isUndefined(clientSideTransitiveSearchDefault) || _.isBoolean(clientSideTransitiveSearchDefault), "clientSideTransitiveSearchDefault must be boolean");
    this.clientSideTransitiveSearchDefault = Boolean(clientSideTransitiveSearchDefault);

    // It seems that ldapjs treats single- and multi-valued attributes the same:
    // - Attributes with no values are not present in the search entries.
    // - Attributes with one value are set to that value, with no enclosing array.
    // - Attributes with more than one value are set to an array of those values.
    // This error-inducing behavior is compensated for in the `getObjects`
    // function below, so that multi-valued attributes are always set to an array.
    // In doing so, this map from attribute name to a bool indicating whether that
    // attribute is single-valued, is consulted. This map is populated by
    // initialize by reading the AD server's schema. However, the
    // overrideSingleValued option passed to the constructor will override the
    // schema, and can be used for attributes that are multi-valued per schema
    // definition but in practice are single-valued.
    assert(_.isPlainObject(overrideSingleValued), "overrideSingleValued must be a plain object");
    assert(
      _.every(_.keys(overrideSingleValued), k => k.match(AttributeNameRE)),
      `Every key in overrideSingleValued must match ${AttributeNameRE}.`,
    );
    assert(
      _.every(_.keys(overrideSingleValued), k => overrideSingleValued[k] === Boolean(overrideSingleValued[k])),
      "Every value in overrideSingleValued must be a boolean.",
    );
    this.dictSingleValued = _.cloneDeep(overrideSingleValued);
    for (const attrib of attributesNeededForInitialization) {
      assert(!(attrib in this.dictSingleValued), `You may not include '${attrib}' in overrideSingleValued.`);
      this.dictSingleValued[attrib] = true; // All of them are single-valued.
    }

    // The application logger
    assert(_.isObject(log), "log missing from ActiveDirectoryHandler config");
    for (const fun of ["debug", "info", "warn", "error", "critical"]) {
      assert(_.isFunction(log[fun]), `log object must have a '${fun}' function.`);
    }
    this.log = log;

    // The AD password
    assert(_.isString(password), "Password must be a string");
    this.password = password;

    // The Base DN for the AD schema
    assert(validDN(schemaConfigBaseDN), "schemaConfigBaseDN must be a valid DN");
    this.schemaConfigBaseDN = schemaConfigBaseDN;

    // The AD connection URL
    assert(_.isString(url), "url must be a string");
    this.url = url;

    // The AD username
    assert(_.isString(user), "user must be a string");
    this.user = user;

    // In AD, the type of a value depends only on the attribute, not the object
    // category/class. Therefore, it's possible to fix encoding/formatting issues
    // right after fetching, with no regard to what the query is. This is a map from
    // attribute name to function used to parse the value before returning it. The
    // function will receive two arguments; ldapjs's attempt to parse it, and the
    // raw buffer received before that attempt. Beyond these hard-coded entries,
    // the initialize function will populate the map using schema information.
    this.extractionFormatters = {
      accountExpires: ldapparsing.dateFormatter_WinNT,
      badPasswordTime: ldapparsing.dateFormatter_WinNT,
      lastLogonTimestamp: ldapparsing.dateFormatter_WinNT,
    };

    // The set of boolean attributes
    this.booleanAttributes = new Set();

    this.initialized = false;

    this.initialize = _.throttle(this.initialize.bind(this), initialize_throttle_delay, { leading: true, trailing: false });
  }

  async initialize(req) {
    // A lot of the time, the correct parse method for an attribute can be
    // determined by the so-called attributeSyntax, which can be found in the
    // domain's schema. For attributes not present in extractionFormatters above,
    // the initialize function will determine a parsing method depending on the
    // attributeSyntax. See https://ldapwiki.com/wiki/2.5.5.1 etc for each
    // attributeSyntax. A null value means we'll rely on ldapjs to parse.
    const extractionFormattersForAttributeSyntax = {
      // DN
      "2.5.5.1": null,
      // OID Syntax. We assume but have not verified that ldapjs can handle it.
      "2.5.5.2": null,
      // CaseIgnoreString
      "2.5.5.4": null,
      // IA5 String / Printable String
      "2.5.5.5": null,
      // Numeric String. We assume but have not verified that ldapjs can handle it.
      "2.5.5.6": null,
      // DNWithOctetString
      "2.5.5.7": null,
      // Boolean
      "2.5.5.8": ldapparsing.ldapBool,
      // Signed 32-bit integer
      "2.5.5.9": ldapparsing.int32,
      // OctetString ("2.5.5.10") has special logic below
      // GeneralizedTime
      "2.5.5.11": ldapparsing.dateFormatter_ADGeneralizedTime,
      // DirectoryString
      "2.5.5.12": null,
      // Presentation Address. We assume but have not verified that ldapjs can
      // handle it.
      "2.5.5.13": null,
      // Object(Access-Point). We assume but have not verified that ldapjs can
      // handle it.
      "2.5.5.14": null,
      // NT-Sec-Desc, no idea how to accurately parse this.
      "2.5.5.15": ldapparsing.ldapBufferToGenericOctetString,
      // LargeInteger.
      "2.5.5.16": null, // BigInt would be more correct
      // Sid
      "2.5.5.17": ldapparsing.ldapBufferToSid,
    };

    const starttime = new Date();
    for await (const item of this.getObjects({
      select: attributesNeededForInitialization,
      from: this.schemaConfigBaseDN,
      where: ["equals", "objectClass", "attributeSchema"],
      waitForInitialization: false,
      req,
    })) {
      // Remember what attributes are multi-valued
      let isv = null;
      if (
        // Test for both 'TRUE' and true since we're in the middle of initialization.
        item.isSingleValued === "TRUE" ||
        item.isSingleValued === true
      ) {
        isv = true;
      } else if (item.isSingleValued === "FALSE" || item.isSingleValued === false) {
        isv = false;
      } else {
        throw futile.err("Could not determine whether ldap attribute is single-valued.", { item });
      }
      if (item.lDAPDisplayName in this.dictSingleValued) {
        if (_.includes(attributesNeededForInitialization, item.lDAPDisplayName)) {
          assert(isv, "Unexpected schema");
        } else {
          assert(this.dictSingleValued[item.lDAPDisplayName] !== isv, "Unnecessary entry in overrideSingleValued or duplicate schema entry");
        }
      } else {
        this.dictSingleValued[item.lDAPDisplayName] = isv;
      }
      // Remember what attributes are boolean
      if (item.attributeSyntax === "2.5.5.8") {
        this.booleanAttributes.add(item.lDAPDisplayName);
      }
      // Assign formatters
      if (item.lDAPDisplayName in this.extractionFormatters) {
        continue;
      }
      if (item.attributeSyntax in extractionFormattersForAttributeSyntax) {
        const f = extractionFormattersForAttributeSyntax[item.attributeSyntax];
        if (f) {
          this.extractionFormatters[item.lDAPDisplayName] = f;
        }
      } else if (item.attributeSyntax === "2.5.5.10") {
        // This is an attribute with OctetString syntax, with no individual
        // parsing function set in extractionFormatters. Let's look at the
        // attribute name and guess whether it's a GUID or not.
        this.extractionFormatters[item.lDAPDisplayName] = item.lDAPDisplayName.match(/G(UID|uid)$/u) ? ldapparsing.ldapBufferToGuid : ldapparsing.ldapBufferToGenericOctetString;
      } else {
        await this.log.warn({ message: "Could not determine parsing method for ldap attribute", item }, req);
      }
    }
    assert(this.dictSingleValued.member === false);
    for (const attrib of ["attributeSyntax", "distinguishedName", "lDAPDisplayName", "member", "objectClass"]) {
      assert(!this.booleanAttributes.has(attrib), `Attribute ${attrib} seems to be boolean. It shouldn't.`);
    }
    this.initialized = true;
    await this.log.debug({ m: "Initialized ActiveDirectoryHandler", time: new Date() - starttime }, req);
  }

  async* getObjects({ select, from = this.domainBaseDN, where = ["true"], clientSideTransitiveSearch = this.clientSideTransitiveSearchDefault, scope = "sub", req, waitForInitialization = true, connection, ...invalidSearchOptions } = {}) {
    const select_all = select === "*";
    // Some validation
    if (!select_all) {
      assert(_.isArray(select) && 1 <= _.size(select) && _.every(select, _.isString), "select must be '*' or a non-empty array of strings");
      assert(
        _.every(select, x => x.match(AttributeNameRE) || x==='_transitive_member' || x==='_transitive_memberOf'),
        `Illegal attribute name in select option. All attribute names must match ${AttributeNameRE}, except for the special attributes '_transitive_member' and '_transitive_memberOf'.`,
      );
      assert(!_.includes(select, "controls"), "ActiveDirectoryHandler.getObjects does not support selecting the field 'controls'");
      assert(!_.includes(select, "dn"), "ActiveDirectoryHandler.getObjects does not support selecting the field 'dn'. Did you perhaps mean 'distinguishedName'?");
    }
    assert(validDN(from), "from must be a valid DN");
    assert(_.isString(scope) && _.includes(["base", "one", "sub"], scope), "scope must be one of 'base', 'one' or 'sub'.");
    assert(_.size(invalidSearchOptions) === 0, `Invalid search option(s) in ActiveDirectoryHandler.getObjects: ${_.keys(invalidSearchOptions)}`);
    const select_includes = select_all ? attribute => attribute in this.dictSingleValued : attribute => _.includes(select, attribute);

    if (waitForInitialization) {
      // Ensure we are initialized
      if (!this.initialized) {
        await this.initialize(req);
      }
      assert(this.initialized);
      // Validate attributes against schema
      if (!select_all) {
        for (const attrib of select) {
          assert(attrib in this.dictSingleValued, `Refuse to fetch non-existent attribute '${attrib}'`);
        }
      }
    }

    // Function to process each item
    const formats = select_all ? this.extractionFormatters : _.pick(this.extractionFormatters, select);
    const add_transitive_member=_.includes(select,'_transitive_member')
    const add_transitive_memberOf=_.includes(select,'_transitive_memberOf')
    const process = async (entry, process_connection) => {
      const obj = entry.object,
        rawobj = { dn: [null] }; // See comment below
      for (const { type, _vals } of entry.attributes) {
        assert(!(type in rawobj), "Unexpectedly, ldapjs returned either an entry for 'dn' or a duplicate entry.");
        rawobj[type] = _vals;
      }
      if (entry.attributes.length === 0) {
        // It seems that in some circumstances, LDAP servers can return entries with no attributes.
        // The circumstances are:
        // - The search should be such that it would return an OU that contains objects you're not allowed to see.
        // - No filters that reference the value of any attributes may be used.
        // - Filters for the existence of an attribute can be OK depending on what attribute it is.
        // Here, we only detect the situation and throw an error.
        throw futile.err(
          'ldapjs parsed an entry with no attributes, when at least one attribute is expected. If you have no need to read this object, it is likely possible to fix this problem by choosing a more restrictive filter. Any filter that somehow restricts the value of an attribute can help, for example ["has", "objectCategory"]; that seems to exclude objects read in this way.',
          { distinguishedName: entry._dn },
        );
      }
      const ret = {};
      // Compensate for ldapjs's quirks, among those the failure to distinguish
      // between single- and multi-valued attributes, as documented above.
      for (let attrib in obj) {
        let value = obj[attrib];
        let rawvalue = rawobj[attrib];
        if (attrib.match(/;range=/u)) {
          // This attribute contained more values than the LDAP server was
          // willing to return. The following workaround provides a consistent
          // interface for the price of a little more memory use.
          const attribMatch = attrib.match(/^([^;]+);range=([0-9]+)-([0-9*]+)$/u);
          assert(attribMatch, `Strange ranged attribute: ${attrib}`);
          const [ignored__match, actualAttributeName, rangeFrom, rangeTo] = attribMatch;
          assert(select_includes(actualAttributeName), select_all ? "Got incomplete value list for non-existent attribute" : "Got incomplete value list for an attribute not asked for.");
          assert(rangeFrom === "0", "Unexpected offset");
          assert(rangeTo !== "*", "Unexpected range syntax");
          assert(_.isEqual(obj[actualAttributeName], []), "Got both complete and incomplete attribute.");
          assert(this.initialized, "Cannot get large ranges during initialization.");
          const data = await this.completeValueRange({ distinguishedName: obj.distinguishedName, attribute: actualAttributeName, connection: process_connection });
          /* eslint-disable-next-line require-atomic-updates */
          attrib = actualAttributeName;
          value = data.values;
          rawvalue = data.rawValues;
        }
        if (!select_includes(attrib)) {
          if (attrib === "controls" || attrib === "dn") {
            // controls and dn attributes are known to be returned without
            // having been asked for. We'll ignore those.
            //
            continue;
          }
          if (attrib === "distinguishedName") {
            // We always ask for distinguishedName for internal reasons.
            // However, in this case it shouldn't be included in ret.
            continue;
          }
          throw futile.err(select_all ? "Got attribute that's not supposed to exist" : "Got attribute without asking for it.", { attrib });
        }
        if (this.dictSingleValued[attrib] === false) {
          // Attribute is multi-valued
          if (_.isArray(value)) {
            // Attribute is multi-valued and value is array, as it should be. Do nothing.
          } else {
            // Attribute is multi-valued but the value needs to be enclosed in an array.
            value = [value];
          }
          assert(value.length === rawvalue.length);
          // Apply format
          if (attrib in formats) {
            value = _.map(_.zip(value, rawvalue), ([val, rawval]) => formats[attrib](val, rawval));
          }
        } else if (this.dictSingleValued[attrib] === true) {
          // Attribute is single-valued
          if (_.isArray(value)) {
            throw Error(`Attribute '${attrib}' is single-valued, but value is an array.`);
          } else {
            // Attribute is single-valued and value is non-array, as it should be. Do nothing.
          }
          assert(rawvalue.length === 1);
          // Apply format
          if (attrib in formats) {
            value = formats[attrib](value, rawvalue[0]);
          }
        } else {
          throw Error(`Missing information about whether attribute '${attrib}' is single-valued.`);
        }
        ret[attrib] = value;
      }
      return ret;
    };

    const attributes = select_all ? "*" : _.filter(_.uniq([...select, "distinguishedName"]), x=>x!=='_transitive_member'&&x!=='_transitive_memberOf')
    const connection_is_external = Boolean(connection);
    try {
      if (!connection_is_external) {
        connection = await this.newConnection();
      }
      const filterExpression = clientSideTransitiveSearch ? await this.rewrite_filter_for_transitive_membership(where, connection, req) : where;
      for await (const entry of this.rawSearch({ attributes, filterExpression, from, scope, connection })) {
        yield await process(entry, connection);
      }
    } finally {
      if (connection && !connection_is_external) {
        await connection.end();
      }
    }
  }

  async newConnection() {
    // Create client
    const ldapClient = ldapjs.createClient({ url: this.url });
    // Promisify
    const bind = promisify(ldapClient.bind).bind(ldapClient);
    const search = promisify(ldapClient.search).bind(ldapClient);
    const unbind = promisify(ldapClient.unbind).bind(ldapClient);
    // Connect and authenticate
    try {
      await bind(this.user, this.password);
    } catch (err) {
      await unbind();
      throw err;
    }
    return { search, end: unbind };
  }

  async* rawSearch({ attributes, filterExpression, from, scope, connection }) {
    assert(connection, "rawSearch called without connection");
    // Send query
    const emitter = await connection.search(from, {
      attributes,
      filter: ldapfilter(filterExpression, this.booleanAttributes),
      scope,
      paged: { pagePause: true },
    });
      // Buffer control
    const buffer = [];
    let should_pause = false;
    let buffer_callback = null;
    let resume_callback = null;
    const bufferctl = function () {
      // Pausing/resuming the event stream is done by not directly calling the
      // callback when receiving a 'page' event. Therefore, pausing is
      // implemented in the generator loop below while resuming is implemented
      // here.
      if (buffer.length > buffer_pause_at_length && !should_pause) {
        should_pause = true;
      }
      if (buffer.length < buffer_resume_at_length && should_pause) {
        should_pause = false;
        if (resume_callback) {
          resume_callback();
          resume_callback = null;
        }
      }
      if (buffer.length && buffer_callback) {
        buffer_callback(true);
        buffer_callback = null;
      }
    };
    emitter.on("searchEntry", entry => {
      buffer.push({ op: "entry", entry });
      bufferctl();
    });
    emitter.on("page", (result, callback) => {
      buffer.push({ op: "page", result, callback });
      bufferctl();
    });
    emitter.on("searchReference", referral => {
      buffer.push({ op: "referral", referral });
      bufferctl();
    });
    emitter.on("error", err => {
      buffer.push({ op: "err", err });
      bufferctl();
    });
    // emitter won't start sending events until there is at least one listener to
    // the "end" event. Since we attach this listener last, we know we won't miss
    // anything.
    emitter.on("end", result => {
      buffer.push({ op: "done", result });
      bufferctl();
    });
    const waitUntilBufferIsNonempty = () =>
      new Promise((resolve, reject) => {
        if (buffer.length) {
          resolve(true);
        } else if (buffer_callback) {
          reject(new Error("This should never happen"));
        } else {
          buffer_callback = resolve;
          bufferctl();
        }
      });
      // Generator
    outer_loop: while (true) {
      // Process for as long as something's available
      while (buffer.length) {
        // First in, first out
        const item = buffer.shift();
        switch (item.op) {
          case "entry":
            yield item.entry;
            break;
          case "page":
            // Encode assumption about how ldapjs works
            assert(!resume_callback);
            // Callback not present at last page
            if (!item.callback) {
              break;
            }
            // Implement back-pressure
            if (should_pause) {
              resume_callback = item.callback;
            } else {
              item.callback();
            }
            break;
          case "referral":
            throw futile.err("ldapjs produced a 'referral', which ActiveDirectoryHandler doesn't know how to handle", { referral: item.referral });
          case "err":
            throw item.err;
          case "done": {
            const { status, errorMessage } = item.result;
            if (status !== 0 || errorMessage !== "") {
              throw futile.err("LDAP error", { status, ldapjsErrorMessage: errorMessage });
            }
            // JavaScript supports breaking to a label but not consecutive breaks.
            break outer_loop;
          }
          default:
            throw Error("This should never happen");
        }
      }
      await waitUntilBufferIsNonempty();
    }
  }

  async getOneObject(arg = {}) {
    const searchresult = [];
    for await (const record of this.getObjects(arg)) {
      searchresult.push(record);
      assert(searchresult.length <= 1);
    }
    assert(searchresult.length === 1);
    return searchresult[0];
  }

  async getObjectsA(args) {
    const ret = [];
    for await (const item of this.getObjects(args)) {
      ret.push(item);
    }
    return ret;
  }

  // Helper function to get all values of one attribute of one object, used in cases where the server isn't willing to send them all in one go.
  async completeValueRange({ distinguishedName, attribute, initValues = [], initRawValues = [], connection }) {
    assert(_.isArray(initValues) && _.isArray(initRawValues) && (initValues.length === initRawValues.length), "Illegal init values");
    assert(connection, "completeValueRange called without connection");
    const OVERLAP = 10;
    const offset = Math.max(0, initValues.length - OVERLAP);
    assert(_.isInteger(offset) && 0 <= offset, "Bad offset");
    const entries = [];
    for await (const entry of this.rawSearch({ attributes: ["distinguishedName", `${attribute};range=${offset}-*`], filterExpression: ["equals", "distinguishedName", distinguishedName], from: distinguishedName, scope: "sub", connection })) {
      entries.push(entry);
    }
    assert(entries.length === 1, "Didn't get exactly one result in getFullRangeOfValues");
    const [entry] = entries;
    let checkedDN = false;
    let gotData = false;
    let data = null;
    for (const { type, _vals } of entry.attributes) {
      if (type === "distinguishedName") {
        assert(!checkedDN, "Duplicate distinguishedName attribute");
        assert(entry.object.distinguishedName === distinguishedName, "Got result for wrong distinguishedName");
        checkedDN = true;
      } else {
        assert(!gotData, "Superfluous attribute");
        const attribMatch = type.match(/^([^;]+);range=([0-9]+)-([0-9*]+)$/u);
        assert(attribMatch, "Unexpected attribute");
        const [ignored__match, actualAttributeName, rangeFrom, rangeTo] = attribMatch;
        assert(actualAttributeName === attribute, "Unexpected ranged attribute");
        assert(`${offset}` === rangeFrom, "Got unwanted range");
        gotData = true;
        data = { vals: entry.object[type], rawvals: _vals, rangeTo };
      }
    }
    assert(checkedDN, "Didn't get distinguishedName in result");
    assert(gotData, "Didn't get data in result");
    assert(_.isArray(data.vals) && _.isArray(data.rawvals) && (data.vals.length === data.rawvals.length), "Got weird data");
    assert(OVERLAP < data.vals.length, "Overlap not covered");
    // For some (probably unfathomably profound) reason, Microsoft LDAP server
    // (or at least ldapjs) seems to consistently return ranged query results in
    // reverse order with repect to whatever order the range refers to.
    const newValues = _.reverse([...data.vals]);
    const newRawValues = _.reverse([...data.rawvals]);
    for (let i = offset; i < initValues.length; i++) {
      assert(_.isEqual(initValues[i], newValues[i - offset]), "Overlap mismatch in values");
      assert(_.isEqual(initRawValues[i], newRawValues[i - offset]), "Overlap mismatch in raw values");
    }
    const concatenatedValues = [...initValues.slice(0, offset), ...newValues];
    const concatenatedRawValues = [...initRawValues.slice(0, offset), ...newRawValues];
    if (data.rangeTo === "*") {
      return { values: newValues, rawValues: newRawValues };
    } else {
      assert(data.rangeTo === `${offset + newValues.length - 1}`, "Inconsistent end of range");
      return this.completeValueRange({ distinguishedName, attribute, initValues: concatenatedValues, initRawValues: concatenatedRawValues, connection });
    }
  }

  // Transitive (a.k.a. in-chain) membership lookup can be performed using the
  // special attribute names "_transitive_member" and "_transitive_memberOf",
  // which use the server-side matching rule LDAP_MATCHING_RULE_IN_CHAIN to
  // perform a transitive search. With the server doing the recursion, the query
  // should be quite performant, but in practice it is inexcusably slow. So,
  // below is an ad-hoc, hacky, chatty, and probably bug-ridden implementation
  // of transitive membership search. Mysteriously, it is faster by 1-2 orders
  // of magnitude.

  async rewrite_filter_for_transitive_membership_Helper_transitiveGroupLookup({ attribute, startingDNs, connection, req }) {
    let toLookup = startingDNs;
    let ret = [];
    while (toLookup.length) {
      const nextLevelGroups = _.map(await this.getObjectsA({
        select: ["distinguishedName"],
        from: this.clientSideTransitiveSearchBaseDN,
        where: ["and", ["equals", "objectClass", "group"], ["equals", "objectCategory", "group"], ["oneof", attribute, toLookup]],
        connection,
        req,
      }), "distinguishedName");
      ret = _.union(ret, toLookup);
      toLookup = _.difference(nextLevelGroups, ret);
    }
    return ret;
  }

  async rewrite_filter_for_transitive_membership_Helper(filter, connection, req) {
    const [op, ...args] = filter;
    if (_.includes(["and", "or", "not"], op)) {
      return [op, ...await Promise.all(_.map(args, x => this.rewrite_filter_for_transitive_membership_Helper(x, connection, req)))];
    }
    if (_.includes(["equals", "oneof"], op) && _.includes(["_transitive_member", "_transitive_memberOf"], args[0])) {
      const [transitive_attrib, value] = args;
      const attrib = { _transitive_member: "member", _transitive_memberOf: "memberOf" }[transitive_attrib];
      const arrayValue = op === "oneof" ? value : [value];
      return ["oneof", attrib, await this.rewrite_filter_for_transitive_membership_Helper_transitiveGroupLookup({ attribute: attrib, startingDNs: arrayValue, connection, req })];
    }
    return filter;
  }

  rewrite_filter_for_transitive_membership(filter, connection, req) {
    assert(connection, "rewrite_filter_for_transitive_membership called without connection");
    ldapfilter(filter, this.booleanAttributes); // Validate filter expression
    return this.rewrite_filter_for_transitive_membership_Helper(filter, connection, req);
  }

  // Integration tests are in a separate file

  async runIntegrationTests({ fraction, req }) {
    await integrationTests.runIntegrationTests({ adHandler: this, fraction, req });
  }
}

module.exports = ActiveDirectoryHandler;
