# Release Notes

## v0.1.0

First published version

## v0.2.0

- **BREAKING CHANGES**:
  - Option `isSingleValued` renamed to `overrideSingleValued`.
  - Error on unexpected lack of attributes. This situation is probably rare.
- Non-breaking API changes:
  - Add filter operators for `true` and `false`.
- Improve/fix README.md, tests, ldapfilter synthesis, boolean handling, etc.

## v0.3.0

Maintenance only.

## v0.4.0

- **BREAKING CHANGE**: Refuse invalid options in config and search.
- Add functionality to select all attributes.
- Add special attributes `_transitive_member` and `_transitive_memberOf`.
- Add search option `clientSideTransitiveSearch`.
- Add config options `clientSideTransitiveSearchBaseDN` and `clientSideTransitiveSearchDefault`.
- Add `getObjectsA` function.
- Various improvements/fixes

## v0.5.0

- Add integration tests.
- Transparent fetching of all values when server returns only some. (Previously only supported for the `member` attribute.)
- Various improvements/fixes.

## v0.5.1

- Updated npm packages
