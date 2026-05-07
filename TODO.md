# TCF v2.3 Support Plan (Revised)

## Phase 0: Core Logic Expansion (Core Methods)
*   **Goal:** Move complex legal basis logic into the library.
*   **Tasks:**
    *   Implement `is_vendor_consent_allowed($vid, $pid)`: Validates Consent bit + Purpose bit + Pub Restrictions.
    *   Implement `is_vendor_legitimate_interest_allowed($vid, $pid)`: Validates LI bit + Purpose bit + Pub Restrictions.
    *   Implement `is_vendor_allowed_for_flexible_purpose($vid, $pid, $default_is_li)`.
    *   Support `strict` mode: `croak` on invalid Purpose IDs (1-24) if enabled, else `warn` and return 0.
    *   **Tests:** New `t/04-legal-basis.t`.

## Phase 1: TCF v2.3 & Segment Robustness
*   **Goal:** Support new segments and fix parsing bugs.
*   **Tasks:**
    *   Implement decoding for **Segment Type 1 (Disclosed Vendors)**.
    *   Implement decoding for **Segment Type 2 (Allowed Vendors)**.
    *   **Fix Segment Overwriting:** Update `_decode_tc_string_segments` to handle multiple segments of the same type safely (e.g., only keep the first occurrence or throw error).
    *   Update `TO_JSON` to include new segments.
    *   **Implement Predicates**:
        *   `has_vendor_disclosure`: Boolean check for Segment Type 1 or 5.
        *   `has_publisher_restrictions`: Boolean check if core segment includes restrictions.
    *   **Implement `vendor_id` filter for `TO_JSON`**:
        *   Support `vendor_id` filter in `Parse` (via `json` options) and direct `TO_JSON` calls.
        *   Filter `vendor` (consents, legitimate_interests, disclosed, allowed) to show only the target ID.
        *   Filter `publisher/restrictions` to only show purposes/restrictions for that target ID.
        *   Maintain structural consistency (return empty map/array if ID not found).
    *   **Implement Automated Release Workflow**:
        *   Create `.github/workflows/release.yml`.
        *   Automate CPAN upload (using PAUSE secrets) and GitHub Release creation on version tags.

## Phase 2: The Validator Interface
*   **Goal:** Automated policy enforcement, TCF v2.3 aware.
*   **Tasks:**
    *   Create `GDPR::IAB::TCFv2::Validator` with constructor + method overrides.
    *   Implement `validate` and `validate_all`.
    *   Implement `GDPR::IAB::TCFv2::Validator::Result` with `$\` (ORS) awareness for stringification.
    *   Include optional check for "Disclosed Vendors" in validation if segment exists.

## Phase 3: Alignment & Cleanup
*   **Goal:** Documentation and nomenclature.
*   **Tasks:**
    *   Update `Purpose.pm` names to TCF v2.3.
    *   Streamline POD and add TCF v2.3 usage examples.

## Phase 4: Performance
*   **Tasks:**
    *   Investigate `vec()` for bitfields.

## Phase 5: CMP Validation
*   **Goal:** IAB Registry-based compliance and automatic CMP lifecycle checks.
*   **Depends on:** Phase 2 (Validator Interface).
*   **Tasks:**
    *   Create `GDPR::IAB::TCFv2::CMPValidator` for querying the official IAB CMP list.
    *   Support flexible registry loading: Local File path, Raw JSON string, or remote URL fetched via `HTTP::Tiny`.
    *   **Compliance Checks:** verify CMP existence in the registry and respect `deletedDate` flags on retired CMPs.
    *   **Stale Data Protection:** emit a warning when registry data is older than 28 days.
    *   **Validator Integration:** expose a `cmp_validator` rule on the main `Validator` interface from Phase 2.
    *   **Tests:** use fixed reference dates so the `deletedDate` / staleness checks are deterministic across execution environments.
*   **Reference:** PR [#38](https://github.com/peczenyj/GDPR-IAB-TCFv2/pull/38) (`feat/phase-5-cmp-validator`, currently OPEN).

## Phase 6: Structured Failure Reporting
*   **Goal:** Bring the Validator's failure-reporting model to parity with the Go `lib-gdpr/validator` package: stable machine-readable codes, structured failure objects, and distinct reasons for each failure mode. Sets the data model for every later phase that introduces new validation rules.
*   **Depends on:** Phase 2 (Validator Interface).
*   **Tasks:**
    *   **6.1 — `Validator::Reason` module:** Create `GDPR::IAB::TCFv2::Validator::Reason` with integer `REASON_*` constants (mirror Go's `code.go` enum: `REASON_NONE`, `REASON_VENDOR_NOT_ALLOWED`, `REASON_VENDOR_NOT_DISCLOSED`, `REASON_PURPOSE_NOT_ALLOWED`, `REASON_VENDOR_NOT_ALLOWED_CONSENT`, `REASON_VENDOR_NOT_ALLOWED_LEGITIMATE_INTEREST`, `REASON_PUBLISHER_RESTRICTION_NOT_ALLOWED`, `REASON_PUBLISHER_RESTRICTION_REQUIRE_CONSENT`, `REASON_PUBLISHER_RESTRICTION_REQUIRE_LEGITIMATE_INTEREST`, `REASON_LEGITIMATE_INTEREST_NOT_PERMITTED_FOR_PURPOSE`, `REASON_POLICY_VERSION_TOO_LOW`, `REASON_MISSING_DISCLOSED_VENDORS`, `REASON_DECODE_ERROR`). Export under `:all`. Provide `reason_string($code)` helper.
    *   **6.2 — `Validator::Failure` value object + `Result` extension:** Lightweight object with `code`, `message`, `purpose_id`, `vendor_id`, `restriction_type`. Extend `Validator::Result` with `failures()` and `reason_codes()` accessors. `reasons()` and the `bool` / `""` overloads stay back-compatible.
    *   **6.3 — TCF carve-out reason:** Detect Purpose 1 LI (always) and Purposes 3-6 LI on policy ≥ 4 in the Validator and emit `REASON_LEGITIMATE_INTEREST_NOT_PERMITTED_FOR_PURPOSE` directly instead of the generic "not allowed (legitimate interest)".
    *   **6.4 — Distinct publisher-restriction reasons:** Have the Validator inspect publisher restrictions itself before delegating to `is_vendor_*_allowed`, so each restriction-type failure surfaces its own reason. Refines the human-readable strings on `reasons()` output (note in `Changes`).
    *   **6.5 — Per-call list overrides:** Allow `validate(..., consent_purpose_ids => [...], legitimate_interest_purpose_ids => [...], flexible_purpose_ids => [...])`. Coherence enforced silently by orphan-drop at runtime (constructor-time still croaks). Empty `[]` distinct from omitted key.
    *   **(Follow-up, non-blocking):** Migrate `CMPValidator` (Phase 5) to emit `Validator::Failure` objects with a `REASON_CMP_*` family (`REASON_INVALID_CMP`, `REASON_CMP_DELETED`, `REASON_CMP_UNKNOWN`).
    *   **Tests:** `t/15-validator-reason.t` (round-trip codes), `t/16-validator-failures.t` (table-driven matrix mirroring the Go `validator_strict_internal_test.go`: list membership × flex flag × restriction type × policy version), per-call-override tests.
*   **Versioning:** ships as **v0.400**.

## Phase 7: GVL-Aware Validator
*   **Goal:** Bridge the IAB Global Vendor List schema to the Phase 2 validator so callers do not have to translate vendor entries by hand.
*   **Depends on:** Phase 2 (Validator Interface).
*   **Tasks:**
    *   Reintroduce `from_gvl_vendor_entry` (deferred from Phase 2): convert a single GVL vendor entry (`{ id, purposes, legIntPurposes, flexiblePurposes }`) into the constructor argument list expected by `Validator->new`.
    *   Add a higher-level `from_gvl(...)` helper that takes a parsed GVL document and a target vendor ID, performs the lookup, and returns a configured `Validator` instance — failing fast if the vendor is missing.
    *   Support flexible GVL input: local file path, raw JSON string, or a parsed hashref.
    *   CLI integration: `iabtcfv2 validate --gvl path/to/gvl.json -v 32 ...` derives the purpose lists from the GVL entry instead of requiring `-C` / `-L` / `-F` on the command line.
    *   **Tests:** golden GVL fixture covering vendors with and without flexible purposes; round-trip `from_gvl_vendor_entry` against a hand-crafted entry.

## Phase 8: Features, Special Features, and Special Purposes
*   **Goal:** Extend the validator beyond standard purposes to cover the rest of the TCF taxonomy.
*   **Depends on:** Phase 2 (Validator Interface), Phase 6 (Structured Failure Reporting — new rules emit `REASON_*` codes from day one).
*   **Tasks:**
    *   Validator support for **Special Features** (opt-in, e.g. precise geolocation): require the bit to be set in the TC string when listed.
    *   Validator support for **Features** (vendor-declared): no consent required, but cross-check that the vendor declares the feature in the GVL once Phase 7 lands.
    *   Validator support for **Special Purposes**: legitimate-interest-only by spec; check vendor declaration without requiring a consent bit.
    *   Surface these on the CLI as `--special-features`, `--features`, `--special-purposes` (comma-separated, same shape as `-C` / `-L`).
    *   **Tests:** extend `t/06-validator.t` with subtests per category; add CLI subtests in `t/10-cli-iabtcfv2.t`.

## Phase 9: CLI Configuration Loading
*   **Goal:** Reduce boilerplate on the command line by letting common flags come from the environment or a config file.
*   **Tasks:**
    *   Map a curated set of environment variables to CLI flags (e.g. `IABTCFV2_VENDOR_ID`, `IABTCFV2_CONSENT_PURPOSES`, `IABTCFV2_LEGITIMATE_INTEREST_PURPOSES`, `IABTCFV2_FLEXIBLE_PURPOSES`, `IABTCFV2_MIN_POLICY_VERSION`). Explicit CLI flags always win.
    *   Optional config file discovery: `.iabtcfv2rc` in the current directory or `$HOME`, plus `.env`-style loading if the file is present. Document the precedence (CLI > env > file > built-in defaults).
    *   Add `iabtcfv2 config` (or `validate --print-config`) to dump the resolved configuration as JSON for debugging.
    *   **Tests:** a CLI subtest that sets the env vars, runs `validate` without the matching flags, and asserts the same outcome as the explicit invocation.

## Distribution
*   [ ] Distribute CLI tool as Docker image via DockerHub.
    *   Create multi-stage `Dockerfile`.
    *   Automate build/push via GitHub Actions.
*   [ ] Distribute library as Debian package (`libgdpr-iab-tcfv2-perl`).
    *   Use `dh-make-perl` to generate `debian/` metadata.
    *   Implement build pipeline for `.deb` artifacts.
