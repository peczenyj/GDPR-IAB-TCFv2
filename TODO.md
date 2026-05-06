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

## Distribution
*   [ ] Distribute CLI tool as Docker image via DockerHub.
    *   Create multi-stage `Dockerfile`.
    *   Automate build/push via GitHub Actions.
*   [ ] Distribute library as Debian package (`libgdpr-iab-tcfv2-perl`).
    *   Use `dh-make-perl` to generate `debian/` metadata.
    *   Implement build pipeline for `.deb` artifacts.
