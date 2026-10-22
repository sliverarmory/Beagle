# Third-party sources

- BloodHound CE v9.8.0, Specter Ops, Inc., Apache License 2.0.
  Commit `1759e1638435595def27eb3ff3c5a6fc32832ddc`.
  Rust ingestion, analysis and composition rules are adapted from `packages/go/ein/ad.go`,
  `cmd/api/src/services/graphify`, and `packages/go/analysis/ad`.
  Relationship shortcut definitions derive from `packages/go/graphschema/ad/ad.go`.
  The Apache license is reproduced in LICENSE. Source: https://github.com/SpecterOps/BloodHound
- BloodHound Query Library, copyright 2025 SpecterOps, MIT License.
  Commit `b1fee8f5715f8fb3358e187ca3f1bddbfd125f93`.
  `data/queries.json` preserves the source query metadata, acknowledgements and resources.
  The license is reproduced in licenses/BloodHound-Query-Library-MIT.txt.
  Source: https://github.com/SpecterOps/BloodHoundQueryLibrary
- GraphQLite and its PCRE2 support are statically linked into Beagle. The build preparation step
  recreates `vendor/graphqlite-source.tar.gz` from checksum-verified public source, pinned to commit
  `fce218994355ebd1162b54ed634791864f1bb81d`. The archive includes GraphQLite's LICENSE
  and bundled PCRE2/SQLite licenses. Per-file hashes are in `vendor/graphqlite-source.json`.
  Source: https://github.com/moloch--/graphqlite
- Windows x64 builds also statically link MSYS2's POSIX regex libraries:
  libsystre 1.0.2 (copyright 2015 LRN) and TRE 0.9.0 (copyright 2001-2009
  Ville Laurikari), both under BSD licenses, plus GNU gettext's libintl 1.0
  and GNU libiconv 1.19, under LGPL 2.1 or later. Package versions, download
  checksums, static library checksums, and source URLs for the verified build
  are recorded in `.github/build/windows-posix.json`. License texts and notices are
  preserved in `licenses/windows-posix/`. These libraries provide the same
  POSIX regex implementation used by GraphQLite's upstream Windows build.
- dawgs v0.9.0, copyright 2025 John Hopper, MIT License.
  Commit `72ea7171b5712e838ff5a174692697c041952d13`.
  Composition traversal semantics follow `graph/path.go`, `traversal/traversal.go`, and
  `ops/traversal.go`, the dependency used by the pinned BloodHound release.
  The license is reproduced in licenses/dawgs-MIT.txt.
  Source: https://github.com/SpecterOps/dawgs
