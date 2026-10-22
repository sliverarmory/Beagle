# Beagle

<p align="center">
  <img src="assets/beagle-logo.png" alt="Beagle project logo" width="320">
</p>

A small, headless Active Directory graph analysis library and CLI built with Rust
and GraphQLite.

## Build

Install Rust stable, Python 3.11–3.14, a C compiler, Make, Bison, and Flex.
On macOS, install a current Bison with Homebrew and add its `bin` directory to
`PATH`. Prepare the pinned public build inputs, then build:

```sh
python3 -m pip install PyYAML==6.0.3
python3 .github/scripts/prepare-build.py
cargo build --locked --release
```

The preparation step downloads checksum-verified GraphQLite source and public
query catalogs. Generated data and vendored sources remain ignored. Private
collections and compatibility validation fixtures are never needed by CI.

Windows builds use the `x86_64-pc-windows-gnu` target and MSYS2 MINGW64. The shared
[build setup](.github/actions/setup-build/action.yml) installs the native build
tools and prepares the pinned static POSIX libraries.

## Checks and releases

[Build checks](.github/workflows/build.yml) run on pushes and pull requests for
Linux x64, macOS ARM64 and Intel, and Windows x64. They check formatting, lint,
test the CLI and library, and run an independent library consumer.

[Releases](.github/workflows/release.yml) run when a `v*` tag is pushed. The tag
must match `Cargo.toml` (for example, `v0.1.0`). Every platform must build and
pass its checks before binary archives, license notices, provenance, and SHA-256
checksums are published to a GitHub release. Release packages contain no private
data or compatibility fixtures.

`ROADMAP.md` is a local planning file and is excluded from Git.
