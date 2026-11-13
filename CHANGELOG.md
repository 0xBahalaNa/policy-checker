# Changelog

## v1.2.0

This entry covers the default CJI pattern expansion in tag v1.2.0. It is not a full list of that tag.

### Changed

- The default CJI set grew from `cji` and `criminal-justice` to five case-insensitive regular expressions: `cji`, `criminal-justice`, `criminal_justice`, `cj-data`, and `cj-info`.
- The checker searches each `Resource` ARN. `cj-info` matches `arn:aws:s3:::old-cj-info-archive/*`. An Allow on that ARN with no MFA condition is a FAIL `cji_missing_mfa`, and the process exits 1.
- `--cji-patterns` replaces the default. The file is a JSON array of pattern strings. The v1.1.0 set is `["cji", "criminal-justice"]`.
