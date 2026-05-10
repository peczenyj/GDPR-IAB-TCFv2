# AGENTS.md

This file provides guidance to coding agents (Claude Code, Copilot CLI, Codex, Gemini CLI, etc.) when working with code in this repository.

## Operational Boundaries

To maintain project integrity and follow the owner's preferred release workflow, **Agents must follow these strict rules**:

1. **NO DIRECT COMMITS TO `devel` OR `main`**: Never commit directly to these branches.
2. **NO MERGING INTO `devel` OR `main`**: Never execute merge commands targeting these branches.
3. **NO TAGGING**: Never create or push git tags.
4. **FEATURE BRANCH WORKFLOW ONLY**:
   - Always work in a dedicated feature branch (`feat/*` or `fix/*`).
   - Sync with `devel` by rebasing or merging `devel` *into* your feature branch if needed.
   - Pushing to the remote feature branch is encouraged for CI verification.
5. **HANDOFF**: Once a task is complete, notify the user or ensure the Pull Request is updated. The project owner will handle all merges and releases.

The canonical IAB spec lives at <https://github.com/InteractiveAdvertisingBureau/GDPR-Transparency-and-Consent-Framework/blob/master/TCFv2/IAB%20Tech%20Lab%20-%20Consent%20string%20and%20vendor%20list%20formats%20v2.md> — keep it in mind when reasoning about bit offsets, segment types, or restriction semantics.

## Build / test commands

This is an `ExtUtils::MakeMaker` distribution. Standard cycle:

```sh
perl Makefile.PL
make
make test                      # runs t/
prove -lr t                    # equivalent, faster iteration
prove -lv t/05-tcf-v23.t       # single test file
prove -lv t/01-parse.t :: --some-arg   # pass args to the test
```

The `.proverc` already adds `-I lib -I t/lib`, so `prove` works without extra flags.

Author tests live in `xt/` and are NOT run by `make test`. Run them explicitly:

```sh
prove -lr xt                   # critic + tidy
make lint                      # perlcritic -profile .perlcriticrc lib bin t xt
make tidy                      # perltidy -b on lib/ bin/ t/ xt/
```

`make tidy` writes `.bak` files next to every reformatted source file (perltidy `-b`). The repo currently contains many such `.bak` files — they are excluded from the dist via `MANIFEST.SKIP` and from author tests via `xt/tidy.t`, but **never edit, commit, or treat them as source**. If you tidy a file and want to discard the backup, delete the `.bak`; do not check it in.

Regenerate the golden test corpus when intentionally changing `TO_JSON` output or parser semantics:

```sh
REGEN_CORPUS=1 prove -lv t/07-golden.t
```

The corpus lives at `t/corpus/golden.jsonl`; the generator is `t/generate_golden.pl` and reads input strings from `t/corpus/gdpr_subset.txt`.

Bump the dist version with the helper instead of hand-editing every `.pm`:

```sh
tools/bump-version 0.402     # rewrites `our $VERSION = "..."` across lib/**.pm
```

The script refuses to downgrade and refuses to run if any `.pm` is missing `$VERSION`.

## Release flow

Documented in `CONTRIBUTING.pod`. Summary: bump `$VERSION` across `lib/**.pm` with `tools/bump-version <new-version>`, run `git cliff -o CHANGELOG.md` (config in `cliff.toml` — uses Conventional Commits), regenerate `README.md` from POD with `pod2markdown lib/GDPR/IAB/TCFv2.pm > README.md`. 

The release process is **automated**: once `devel` is merged to `main`, pushing a tag (`v*`) triggers a GitHub Action (`.github/workflows/release.yml`) that builds the distribution, uploads to CPAN (PAUSE), and creates a GitHub Release with the tarball attached.

Commits are expected to follow Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, …) so `git cliff` can group them correctly. Patches target the `devel` branch, not `main`.

## Architecture

The parser is a single-pass bit-stream decoder over the base64url-decoded TC string. Understanding three things explains the rest of the code:

1. **Segments.** A TC string is `<core>.<segment>.<segment>...`, separated by `.`. The first segment is always Core; subsequent segments self-identify via a 3-bit `segment_type` header (`1` = Disclosed Vendors, `2` = Allowed Vendors, `3` = Publisher TC). `_decode_tc_string_segments` in `lib/GDPR/IAB/TCFv2.pm` splits and routes them into `core_data`, `disclosed_vendors_data`, `allowed_vendors_data`, `publisher_tc_data`.

2. **Bit offsets are spec-driven constants.** `lib/GDPR/IAB/TCFv2.pm` defines an `OFFSETS` constant hash mapping each Core field (`VERSION`, `CREATED`, `CMP_ID`, `PURPOSE_CONSENT_ALLOWED`, …) to its starting bit. Accessor methods (`version`, `cmp_id`, `is_purpose_consent_allowed`, …) are thin wrappers that call helpers from `BitUtils` (`is_set`, `get_uint6/12/16/36`, `get_char6_pair`) at those offsets. **Do not invent new offsets** — cross-check the IAB spec table.

3. **Vendor lists use one of two encodings.** After the fixed Core header, the vendor consent / LI sections begin with a 1-bit flag selecting either:
   - **BitField** (`lib/GDPR/IAB/TCFv2/BitField.pm`) — one bit per vendor up to `max_vendor_id`. O(1) lookup.
   - **RangeSection** (`lib/GDPR/IAB/TCFv2/RangeSection.pm`) — list of `(start, end)` ranges. O(N) lookup unless the caller passes `prefetch => [vendor_ids]` to `Parse`, which pre-walks ranges and caches answers — important for hot paths over range-encoded strings.

   The same BitField/RangeSection pair is reused for the Disclosed Vendors and Allowed Vendors segments.

### Module layout

- `lib/GDPR/IAB/TCFv2.pm` — entry point; `Parse()` constructor, all top-level accessors, JSON serialization (`TO_JSON`) with `vendor_id` filtering support, version/policy/structure predicates (`is_v22_plus`, `is_v23`, `has_vendor_disclosure`, `has_publisher_restrictions`).
- `lib/GDPR/IAB/TCFv2/BitUtils.pm` — pure-function bit readers, exported on demand. Detects `pack 'Q>'` availability at `BEGIN` to handle 32-bit Perls (falls back via `Math::BigInt`).
- `lib/GDPR/IAB/TCFv2/BitField.pm`, `RangeSection.pm` — vendor-list decoders (see above).
- `lib/GDPR/IAB/TCFv2/Publisher.pm` — wraps `PublisherRestrictions` (always present in Core) and `PublisherTC` (optional segment type 3).
- `lib/GDPR/IAB/TCFv2/PublisherRestrictions.pm` — decodes purpose×vendor restriction overrides from the Core segment tail.
- `lib/GDPR/IAB/TCFv2/PublisherTC.pm` — decodes the optional Publisher TC segment.
- `lib/GDPR/IAB/TCFv2/Constants/{Purpose,SpecialFeature,RestrictionType}.pm` — exportable numeric constants matching the IAB Global Vendor List. These are part of the public API; renaming them is a breaking change.

### Spec rules baked into the code (don't "simplify" away)

- **Purpose 1 never permits Legitimate Interest** — hard-coded in `is_purpose_legitimate_interest_allowed`.
- **TCF v2.2+ (policy_version ≥ 4) prohibits LI for Purposes 3, 4, 5, 6** — also enforced there.
- **`strict` mode** rejects strings whose `version` field isn't 2, and (for v2.3 / policy_version ≥ 5) requires the Disclosed Vendors segment to be present.
- **`is_service_specific` must be 1** per spec; the library currently exposes the raw bit rather than rejecting `0`. See `README.md` `is_service_specific` for context.
- `TCF_V23_DEADLINE` constant (`1772236800` = 2026-02-28) marks when v2.3 becomes mandatory in the wild — referenced for forward-compat logic.

### CLI

`bin/iabtcfv2` is a subcommand-style tool (currently only `dump` is implemented; `validate` is reserved). The `dump` command supports `--strict` (enforces TCF v2.3 rules) and `--vendor-id` (`-v`) to filter output. 

It uses POD for both `--help` and `perldoc iabtcfv2`, with `Pod::Usage` selecting sections (`SYNOPSIS|OPTIONS|SUBCOMMANDS`, `DUMP`). When adding a subcommand, mirror this pattern: add a `run_<name>` sub, add a `=head1 <NAME>` section to the trailing POD, and dispatch from the top-level `if/elsif` chain. The CLI is included in the dist via `EXE_FILES` in `Makefile.PL` and is the entrypoint of the Docker image.

### Tests

Numbered conventionally: `00-load`, `01-parse`, `02-json-bitfield`, `03-json-range`, `04-legal-basis`, `05-tcf-v23`, `07-golden`, `09-predicates`, `10-cli-iabtcfv2`, `90-bugs`, `99-pod`. The CLI test (`10-cli-iabtcfv2.t`) shells out to `bin/iabtcfv2` — it needs the script to be executable. The golden test (`07-golden.t`) is a regression net for `TO_JSON` and key sampling assertions; treat unexpected mismatches as bugs first, regenerate the corpus only after confirming the behavior change is intended.

## Style

`.perlcriticrc` (severity 3) and `.perltidyrc` (79-col, 4-space indent, `--break-at-old-comma-breakpoints`) are authoritative — run `make tidy` before committing non-trivial edits or CI's tidy job will fail. The codebase uses `use integer; use bytes;` in hot bit-manipulation modules; preserve those pragmas when editing `BitUtils`, `BitField`, `RangeSection`, or the main parser.
