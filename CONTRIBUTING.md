# Contributing

## Build and test

```sh
cargo build --locked
cargo test --locked
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo deny check advisories licenses bans sources
```

The minimum supported Rust version is the `rust-version` in `Cargo.toml`; CI builds with it.
Install the [prek](https://github.com/j178/prek) (or pre-commit) hooks with
`prek install`: they run rustfmt, clippy and gitleaks. Warnings are errors.

## Adding a rule

1. Pick the module that matches what the rule reads, and use the next free id in its range
   (the range is stated in the module's doc comment):

   | Module | Ids |
   | --- | --- |
   | `src/rules/injection.rs` | MW001-MW009 |
   | `src/rules/hidden.rs` | MW010-MW019 |
   | `src/rules/exfil.rs` | MW020-MW029 |
   | `src/rules/config_rules.rs` | MW100-MW119 |
   | `src/pin.rs` | MW200-MW209 |

2. Add a `RuleInfo` entry (id, kebab-case name, severity, one-line summary, help text) to the
   module's `RULES`. Ids must be unique and every rule needs a summary and help text; a unit
   test in `src/rules/mod.rs` enforces this.
3. Implement the check in the module's `check` function and add unit tests for a hit and
   for a near miss that must stay quiet.
4. Add a corpus case under `tests/corpus/`: a sample that triggers the rule and, where
   useful, a benign one that does not. Fake secrets in `tests/fixtures/` and `tests/corpus/`
   are allowed by `.gitleaks.toml`; never use real credentials.

## Pull requests

Keep one logical change per pull request and describe what the diff does. Pin any new GitHub
Action to a full commit SHA with a version comment.
