"use strict";
/* global test, expect */
const package_json = require("./package.json");
const package_lock_json = require("./package-lock.json");
const version_in_package_json = package_json.version;
const version_in_package_lock_json = package_lock_json.version;
const fs = require("fs");
const RELEASE_NOTES_md = "" + fs.readFileSync("./RELEASE_NOTES.md");
const eslint = require("eslint");
const jest_ = require("jest");
const prettier = require("prettier");

test("Version", () => {
  expect(version_in_package_lock_json).toBe(version_in_package_json);
  expect(version_in_package_json).toMatch(/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u);
  const rn_headings = RELEASE_NOTES_md.split("\n").filter(x => x.match(/^#/u));
  const first_rn_heading = rn_headings[0];
  const version_rn_headings = rn_headings.slice(1);
  const last_rn_heading = rn_headings[rn_headings.length - 1];
  expect(first_rn_heading).toBe("# Release Notes");
  for (const version_rn_heading of version_rn_headings) {
    expect(version_rn_heading).toMatch(/^## v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u);
  }
  expect(last_rn_heading).toBe(`## v${version_in_package_json}`);
  expect(eslint.ESLint.version).toBe(package_json.devDependencies.eslint);
  expect(jest_.getVersion()).toBe(package_json.devDependencies.jest);
  expect(prettier.version).toBe(package_json.devDependencies.prettier);
});
