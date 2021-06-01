"use strict";
const assert = require("assert");
const futile = require("@fujitsusweden/futile");
const _ = require("lodash");

const CHUNK_SIZE_ATTRIBUTES = 4;
const CHUNK_SIZE_GROUPS = 20;
const CHUNK_SIZE_USERS = 36;

function randomSelection(array, fraction) {
  assert(_.isArray(array), "randomSelection can only be performed on an array.");
  assert(_.isNumber(fraction), "fraction must be a number.");
  assert(0 <= fraction && fraction <= 1, "fraction must be in the 0-1 range.");
  const scrambled = _.sortBy(array, () => Math.random());
  assert(scrambled.length === array.length);
  return scrambled.slice(0, Math.ceil(fraction * scrambled.length));
}

async function chunkedProcess({ process, input, onProgress, chunkSize }) {
  let last_report = -1;
  for (let i = 0; i < input.length; i += chunkSize) {
    /* eslint-disable-next-line no-magic-numbers */
    const percentage_done = Math.floor(100 * i / input.length);
    if (last_report < percentage_done) {
      await onProgress(percentage_done);
      last_report = percentage_done;
    }
    await Promise.all(_.map(input.slice(i, i + chunkSize), process));
  }
  const DONE_PERCENT = 100;
  if (last_report < DONE_PERCENT) {
    await onProgress(DONE_PERCENT);
  }
}

async function ensureSameResults({ adHandler, req, query1, query2 }) {
  // Use the same connection for both queries, so that we won't fail on differences between servers
  const connection = await adHandler.newConnection();
  try {
    for (const attempt of ["first", "last"]) {
      const [onlyIn1, ignored__both, onlyIn2] = futile.diffIntDiff(await adHandler.getObjectsA({ ...query1, connection, req }), await adHandler.getObjectsA({ ...query2, connection, req }));
      if (onlyIn1.length || onlyIn2.length) {
        if (attempt === "last") {
          await adHandler.log.warn({ m: "These two queries should have produced the same results, but they didn't.", query1, query2, onlyIn1, onlyIn2 }, req);
          return;
        }
      } else {
        return;
      }
    }
  } finally {
    await connection.end();
  }
}

async function ensureInitialized({ adHandler, req }) {
  if (!adHandler.initialized) {
    await adHandler.initialize(req);
  }
  assert(adHandler.initialized, "Initialization ineffective");
}

/* eslint-disable-next-line complexity */
async function testOneAttribute({ adHandler, attribute, req, method = 1 }) {
  await ensureInitialized({ adHandler, req });
  try {
    const isv = adHandler.dictSingleValued[attribute];
    let hasone = false;
    let hasmulti = false;
    let hasWarnedAboutMissingAttribute = false;
    for (const from of [adHandler.domainBaseDN, adHandler.schemaConfigBaseDN]) {
      let where = ["has", attribute];
      if (_.includes(["distinguishedName", "objectClass", "objectGUID", "name"], attribute)) {
        where = ["and", ["has", attribute], ["has", "objectCategory"]];
      }
      /* eslint-disable-next-line no-magic-numbers */
      if (method === 2) {
        where = ["has", "objectCategory"];
      }
      for await (const item of adHandler.getObjects({ select: ["distinguishedName", attribute], from, where, req })) {
        const { distinguishedName } = item;
        if (!(attribute in item)) {
          if (!hasWarnedAboutMissingAttribute && method === 1) {
            await adHandler.log.warn({ m: "Attribute not returned even though filtered on. Ignore this warning if you're not supposed to have read access to this attribute.", attribute, isv, from, distinguishedName_example: distinguishedName }, req);
            hasWarnedAboutMissingAttribute = true;
          }
          continue;
        }
        const value = item[attribute];
        if (!isv) {
          if (!Array.isArray(value)) {
            await adHandler.log.error({ m: "Multi-valued attribute should always be returned as an array", attribute, isv, from, distinguishedName, value }, req);
          }
          if (method === 1 && 0 === value.length) {
            await adHandler.log.error({ m: "Query with 'has' filter should not return entries with zero values", attribute, isv, from, distinguishedName, value }, req);
          }
          if (1 === value.length) {
            hasone = true;
          }
          if (1 < value.length) {
            hasmulti = true;
          }
        }
      }
    }
    if (!isv && hasone && !hasmulti) {
      await adHandler.log.info(
        {
          m:
                "This attribute is declared as multi-valued, but the maximum number of values for any entry is 1. If you know this will always be the case and want to deal with these values without an enclosing array, you can add it to the 'overloadSingleValued' option.",
          attribute,
          isv,
        },
        req,
      );
    }
  } catch (err) {
    if (method === 1 && ("lde_message" in err) && err.lde_message.match(/problem 1004 \(WRONG_MATCH_OPER\)/u)) {
      await testOneAttribute({ adHandler, attribute, req, method: 2 });
    } else if (("lde_message" in err) && err.lde_message.match(/problem 5012 \(DIR_ERROR\)/u)) {
      await adHandler.log.warn({ err, attribute, explanation: "This can happen if certain attributes are included in the select option. If you never need to read this attribute, then don't worry about it." }, req);
    } else {
      await adHandler.log.error({ err, attribute }, req);
    }
  }
}

async function testAttributes({ adHandler, fraction = 1, req }) {
  await ensureInitialized({ adHandler, req });
  await adHandler.log.debug({ begin_job: "testAttributes" }, req);
  await chunkedProcess({
    chunkSize: CHUNK_SIZE_ATTRIBUTES,
    input: randomSelection(_.keys(adHandler.dictSingleValued), fraction),
    async process(attribute) {
      await testOneAttribute({ adHandler, attribute, req });
    },
    async onProgress(percentage_done) {
      await adHandler.log.debug({ job: "testAttributes", percentage_done }, req);
    },
  });
}

async function testOneGroup({ adHandler, distinguishedName, req }) {
  await ensureInitialized({ adHandler, req });
  await ensureSameResults({
    adHandler,
    req,
    query1: { select: ["distinguishedName"], where: ["and", ["equals", "objectClass", "group"], ["equals", "objectCategory", "group"], ["equals", "_transitive_member", distinguishedName]], clientSideTransitiveSearch: true },
    query2: { select: ["distinguishedName"], where: ["and", ["equals", "objectClass", "group"], ["equals", "objectCategory", "group"], ["equals", "_transitive_member", distinguishedName]], clientSideTransitiveSearch: false },
  });
  await ensureSameResults({
    adHandler,
    req,
    query1: { select: ["distinguishedName"], where: ["and", ["equals", "objectClass", "group"], ["equals", "objectCategory", "group"], ["equals", "_transitive_memberOf", distinguishedName]], clientSideTransitiveSearch: true },
    query2: { select: ["distinguishedName"], where: ["and", ["equals", "objectClass", "group"], ["equals", "objectCategory", "group"], ["equals", "_transitive_memberOf", distinguishedName]], clientSideTransitiveSearch: false },
  });
}

async function testGroups({ adHandler, fraction = 1, req }) {
  await ensureInitialized({ adHandler, req });
  await adHandler.log.debug({ begin_job: "testGroups" }, req);
  for await (const item of adHandler.getObjects({
    select: ["distinguishedName"],
    where: ["and", ["has", "member"], ["not", ["and", ["equals", "objectClass", "group"], ["equals", "objectCategory", "group"]]]],
    req,
  })
  ) {
    const { distinguishedName } = item;
    await adHandler.log.warn({ m: "This object has a member without being a group. That violates an important assumption.", distinguishedName }, req);
  }
  await chunkedProcess(
    {
      chunkSize: CHUNK_SIZE_GROUPS,
      input: randomSelection(await adHandler.getObjectsA({ select: ["distinguishedName"], where: ["and", ["equals", "objectClass", "group"], ["equals", "objectCategory", "group"]], req }), fraction),
      async process({ distinguishedName }) {
        await testOneGroup({ adHandler, distinguishedName, req });
      },
      async onProgress(percentage_done) {
        await adHandler.log.debug({ job: "testGroups", percentage_done }, req);
      },
    },
  );
}

async function testOneUser({ adHandler, distinguishedName, req }) {
  await ensureInitialized({ adHandler, req });
  await ensureSameResults({
    adHandler,
    req,
    query1: { select: ["distinguishedName"], where: ["and", ["equals", "objectClass", "group"], ["equals", "objectCategory", "group"], ["equals", "_transitive_member", distinguishedName]], clientSideTransitiveSearch: true },
    query2: { select: ["distinguishedName"], where: ["and", ["equals", "objectClass", "group"], ["equals", "objectCategory", "group"], ["equals", "_transitive_member", distinguishedName]], clientSideTransitiveSearch: false },
  });
}

async function testUsers({ adHandler, fraction = 1, req }) {
  await ensureInitialized({ adHandler, req });
  await adHandler.log.debug({ begin_job: "testUsers" }, req);
  await chunkedProcess(
    {
      chunkSize: CHUNK_SIZE_USERS,
      input: randomSelection(await adHandler.getObjectsA({ select: ["distinguishedName"], where: ["and", ["equals", "objectClass", "user"], ["equals", "objectCategory", "person"]], req }), fraction),
      async process({ distinguishedName }) {
        await testOneUser({ adHandler, distinguishedName, req });
      },
      async onProgress(percentage_done) {
        await adHandler.log.debug({ job: "testUsers", percentage_done }, req);
      },
    },
  );
}

async function runIntegrationTests({ adHandler, fraction = 1, req }) {
  assert(!adHandler.initialized, "integrationTests must be called on a new instance of ActiveDirectoryHandler, before any searches are run.");
  assert(_.isEqual(await adHandler.getObjectsA({ select: ["distinguishedName"], where: ["false"], req }), []), 'Records returned despite ["false"] filter.');
  assert(adHandler.initialized, "Searching should cause initialization");
  await Promise.all([
    testAttributes({ adHandler, fraction, req }),
    testGroups({ adHandler, fraction, req }),
    testUsers({ adHandler, fraction, req }),
  ]);
}

module.exports = {
  testOneAttribute,
  testAttributes,
  testOneGroup,
  testGroups,
  testOneUser,
  testUsers,
  runIntegrationTests,
};
