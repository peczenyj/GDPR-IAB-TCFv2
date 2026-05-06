# Vendor Segment Parser Cleanup — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Address the four residual observations from the deep-dive review of `_parse_vendor_bitfield_or_range` so the segment-decoding code is internally consistent, defensively robust, and spec-compliant on the `MaxVendorId == 0` edge case.

**Architecture:** All changes are local to `lib/GDPR/IAB/TCFv2.pm`. Two helpers (`_parse_bitfield`, `_parse_range_section`) are aligned to the new helper's `data_size` convention; one (`_parse_vendor_bitfield_or_range`) gains an expected-segment-type assertion, an explanatory comment, and a `max_id == 0` short-circuit. Tests live in `t/05-tcf-v23.t` (extends existing v2.3 segment coverage). No public API changes; the work is observable only through new error messages on malformed input.

**Tech Stack:** Perl 5.008+, `ExtUtils::MakeMaker`, `Test::More`, `Test::Exception`, `prove`. No new dependencies.

**Operational note:** Per `AGENTS.md`, all work happens on a feature branch (`fix/vendor-segment-parser-cleanup`). Do not commit to `devel`/`main`, do not merge into them, do not create tags. Hand off via PR when complete.

**Branch naming:** `fix/vendor-segment-parser-cleanup`. Branch from current `devel`.

**Pre-flight (run before Task 1):**

```bash
git fetch origin
git checkout -b fix/vendor-segment-parser-cleanup origin/devel
perl Makefile.PL && make
prove -lr t          # baseline: must be green before any change
```

If baseline is not green, stop and investigate — no point fixing cleanup issues on top of a broken tree.

---

### Task 1: Align `data_size` in core helpers to slice length

**Issue addressed:** Residual #1 from the review — `_parse_bitfield` and `_parse_range_section` pass `data_size => length($self->{core_data})` (full core, in bits) alongside a sliced `$data`. The new `_parse_vendor_bitfield_or_range` already does the right thing (`length($slice)`); this task ports the pattern back so `data_size` faithfully describes what the callee receives. For typical valid TC strings this is purely cosmetic; for truncated cores with very small `max_id` it tightens the existing `data_size < $max_id` guard in `BitField->Parse`.

**Files:**
- Modify: `lib/GDPR/IAB/TCFv2.pm:921-936` (`_parse_range_section`)
- Modify: `lib/GDPR/IAB/TCFv2.pm:942-954` (`_parse_bitfield`)
- Test: `t/05-tcf-v23.t` (append a new subtest)

- [ ] **Step 1: Inspect both helpers and confirm current line ranges**

```bash
grep -n "^sub _parse_bitfield\b\|^sub _parse_range_section" lib/GDPR/IAB/TCFv2.pm
sed -n '921,955p' lib/GDPR/IAB/TCFv2.pm
```

Expected output: two helpers, each computing `my $data_size = length( $self->{core_data} );` then passing it through to `BitField->Parse` / `RangeSection->Parse`.

- [ ] **Step 2: Write the failing test**

Append the following subtest to `t/05-tcf-v23.t` (just before `done_testing` if present, otherwise at the end of the file):

```perl
subtest "BitField data_size reflects slice length, not full core" => sub {
    # Construct a malformed Core that claims max_id_consent = 24 (the
    # purpose-allowed field width happens to leave 24 bits) but truncates
    # the bitfield payload. With the OLD code, data_size = length(core)
    # could exceed max_id and let the truncation slip past Parse;
    # with the NEW code, data_size == slice length and the croak fires.
    #
    # We build the smallest reproducible case: take a known-good v2.0
    # consent string and chop bytes off the END, leaving the bitfield
    # claim intact but the payload short.
    my $good =
      'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA';

    # Sanity: the unmodified string parses cleanly.
    lives_ok { GDPR::IAB::TCFv2->Parse($good) } 'baseline parses';

    # Truncate by removing the trailing 4 base64 chars (~24 bits payload).
    my $truncated = substr( $good, 0, length($good) - 4 );

    throws_ok { GDPR::IAB::TCFv2->Parse($truncated) }
      qr/BitField for \d+ bits requires a consent string of at least \d+ bits/,
      'truncated bitfield is rejected with slice-aware size in error message';
};
```

- [ ] **Step 3: Run the new test against unmodified code**

Run: `prove -lv t/05-tcf-v23.t`

Expected: the new subtest may pass *or* fail today depending on whether the truncation is large enough to fall under either size. Note the actual outcome — if it already passes, that proves the existing code happens to catch this case via a different bound; the data_size alignment is then pure cleanup. If it fails, the alignment fix in Step 4 will make it pass.

- [ ] **Step 4: Update `_parse_range_section` to pass slice length**

Edit `lib/GDPR/IAB/TCFv2.pm:921-936`. Replace:

```perl
sub _parse_range_section {
    my ( $self, $max_id, $range_section_start_offset ) = @_;

    my $data      = substr( $self->{core_data}, $range_section_start_offset );
    my $data_size = length( $self->{core_data} );

    my ( $range_section, $next_offset ) =
      GDPR::IAB::TCFv2::RangeSection->Parse(
        data      => $data,
        data_size => $data_size,
        offset    => 0,
        max_id    => $max_id,
        options   => $self->{options},
      );

    return
      wantarray
      ? ( $range_section, $range_section_start_offset + $next_offset )
      : $range_section;
}
```

with:

```perl
sub _parse_range_section {
    my ( $self, $max_id, $range_section_start_offset ) = @_;

    my $data = substr( $self->{core_data}, $range_section_start_offset );

    my ( $range_section, $next_offset ) =
      GDPR::IAB::TCFv2::RangeSection->Parse(
        data      => $data,
        data_size => length($data),
        offset    => 0,
        max_id    => $max_id,
        options   => $self->{options},
      );

    return
      wantarray
      ? ( $range_section, $range_section_start_offset + $next_offset )
      : $range_section;
}
```

- [ ] **Step 5: Update `_parse_bitfield` to pass slice length**

Edit `lib/GDPR/IAB/TCFv2.pm:942-954`. Replace:

```perl
sub _parse_bitfield {
    my ( $self, $max_id, $bitfield_start_offset ) = @_;

    my $data = substr( $self->{core_data}, $bitfield_start_offset, $max_id );
    my $data_size = length( $self->{core_data} );

    my ( $bitfield, $next_offset ) = GDPR::IAB::TCFv2::BitField->Parse(
        data      => $data,
        data_size => $data_size,
        max_id    => $max_id,
        options   => $self->{options},
    );

    return wantarray
      ? ( $bitfield, $bitfield_start_offset + $next_offset )
      : $bitfield;
}
```

with:

```perl
sub _parse_bitfield {
    my ( $self, $max_id, $bitfield_start_offset ) = @_;

    my $data = substr( $self->{core_data}, $bitfield_start_offset, $max_id );

    my ( $bitfield, $next_offset ) = GDPR::IAB::TCFv2::BitField->Parse(
        data      => $data,
        data_size => length($data),
        max_id    => $max_id,
        options   => $self->{options},
    );

    return wantarray
      ? ( $bitfield, $bitfield_start_offset + $next_offset )
      : $bitfield;
}
```

- [ ] **Step 6: Re-run the full test suite**

Run: `prove -lr t`

Expected: all tests green, including the new subtest from Step 2.

- [ ] **Step 7: Run author tests to confirm style**

Run: `prove -lr xt`

Expected: green. If `xt/tidy.t` complains, run `make tidy` and stage the resulting changes (delete the `.bak` files it leaves behind — do NOT commit them).

- [ ] **Step 8: Commit**

```bash
git add lib/GDPR/IAB/TCFv2.pm t/05-tcf-v23.t
git commit -m "fix: align core bitfield/range data_size to slice length

Both _parse_bitfield and _parse_range_section previously passed the
full core_data bit-length as data_size while passing a sliced \$data.
This made the BitField/RangeSection size validation lenient for
truncated cores with small max_id values. Align with the pattern
already used in _parse_vendor_bitfield_or_range."
```

---

### Task 2: Defensive segment-type assertion in `_parse_vendor_bitfield_or_range`

**Issue addressed:** Residual #2 — the helper trusts `_decode_tc_string_segments` to have routed the segment correctly, but never validates that bits 0-2 of the slice actually equal the expected segment type. `PublisherTC->Parse` does this defensively; this task brings the new helper to parity.

**Files:**
- Modify: `lib/GDPR/IAB/TCFv2.pm:837-883` (`_parse_disclosed_vendors`, `_parse_allowed_vendors`, `_parse_vendor_bitfield_or_range`)
- Test: `t/05-tcf-v23.t` (extend the existing "TCF v2.3 segments" subtest or add a new one)

- [ ] **Step 1: Write the failing test**

Append to `t/05-tcf-v23.t`:

```perl
subtest "Disclosed Vendors helper rejects mis-typed payload" => sub {
    # Hand-craft a "Disclosed Vendors" segment whose first 3 bits claim
    # segment_type=2 (Allowed Vendors) instead of 1.  The router would
    # never feed this through _parse_disclosed_vendors today, but the
    # helper itself should still reject it as defense-in-depth.
    #
    # We exercise the helper by calling it directly via a private hook.
    use GDPR::IAB::TCFv2;
    my $consent = GDPR::IAB::TCFv2->Parse(
        'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA'
    );

    # Build a fake segment payload: 3 bits = 010 (=2), then a benign
    # MaxVendorId=0, IsRangeEncoding=0 tail.
    my $bad = '010' . ( '0' x 16 ) . '0';

    throws_ok {
        $consent->_parse_vendor_bitfield_or_range(
            $bad,
            GDPR::IAB::TCFv2::SEGMENT_TYPES->{DISCLOSED_VENDORS},
        );
    }
      qr/invalid segment type/,
      'helper croaks when payload header does not match expected type';
};
```

- [ ] **Step 2: Run the new test**

Run: `prove -lv t/05-tcf-v23.t`

Expected: FAIL — current helper signature does not accept an expected-type argument and does not check the header.

- [ ] **Step 3: Add expected-type parameter and assertion**

Edit `lib/GDPR/IAB/TCFv2.pm:856-883`. Replace the signature line and add a header check immediately after reading `$max_id`:

```perl
sub _parse_vendor_bitfield_or_range {
    my ( $self, $data, $expected_segment_type ) = @_;

    my $offset = 0;

    my ( $segment_type, $next_offset ) = get_uint3( $data, $offset );

    croak
      "invalid segment type $segment_type: expected $expected_segment_type"
      if defined $expected_segment_type
      && $segment_type != $expected_segment_type;

    $offset = $next_offset;

    my ( $max_id, $next_offset_after_max ) = get_uint16( $data, $offset );

    my ( $is_range, $bf_offset ) = is_set( $data, $next_offset_after_max );

    my $vendors_section;
    if ($is_range) {
        my $range_data = substr( $data, $bf_offset );
        ( $vendors_section, ) = GDPR::IAB::TCFv2::RangeSection->Parse(
            data      => $range_data,
            data_size => length($range_data),
            offset    => 0,
            max_id    => $max_id,
            options   => $self->{options},
        );
    }
    else {
        my $bitfield_data = substr( $data, $bf_offset, $max_id );
        ( $vendors_section, ) = GDPR::IAB::TCFv2::BitField->Parse(
            data      => $bitfield_data,
            data_size => length($bitfield_data),
            max_id    => $max_id,
            options   => $self->{options},
        );
    }

    return $vendors_section;
}
```

Note: `get_uint3` must already be in the import list at the top of the module (it is — see the `use GDPR::IAB::TCFv2::BitUtils` block). If linting flags an unused import after the change, leave it alone — `get_uint3` is now used here.

- [ ] **Step 4: Update both callers to pass the expected type**

Edit `lib/GDPR/IAB/TCFv2.pm:837-850`. Replace:

```perl
sub _parse_disclosed_vendors {
    my $self = shift;

    return unless defined $self->{disclosed_vendors_data};

    $self->{disclosed_vendors} =
      $self->_parse_vendor_bitfield_or_range(
        $self->{disclosed_vendors_data} );
}

sub _parse_allowed_vendors {
    my $self = shift;

    return unless defined $self->{allowed_vendors_data};

    $self->{allowed_vendors} =
      $self->_parse_vendor_bitfield_or_range( $self->{allowed_vendors_data} );
}
```

with:

```perl
sub _parse_disclosed_vendors {
    my $self = shift;

    return unless defined $self->{disclosed_vendors_data};

    $self->{disclosed_vendors} = $self->_parse_vendor_bitfield_or_range(
        $self->{disclosed_vendors_data},
        SEGMENT_TYPES->{DISCLOSED_VENDORS},
    );
}

sub _parse_allowed_vendors {
    my $self = shift;

    return unless defined $self->{allowed_vendors_data};

    $self->{allowed_vendors} = $self->_parse_vendor_bitfield_or_range(
        $self->{allowed_vendors_data},
        SEGMENT_TYPES->{ALLOWED_VENDORS},
    );
}
```

- [ ] **Step 5: Run the new test and the full suite**

Run: `prove -lv t/05-tcf-v23.t && prove -lr t`

Expected: PASS for the new subtest; full suite green.

- [ ] **Step 6: Run author tests**

Run: `prove -lr xt`

Expected: green. Run `make tidy` if needed; delete the resulting `.bak` files.

- [ ] **Step 7: Commit**

```bash
git add lib/GDPR/IAB/TCFv2.pm t/05-tcf-v23.t
git commit -m "feat: defensive segment-type check in vendor-segment helper

_parse_vendor_bitfield_or_range now accepts an expected_segment_type
argument and croaks if the payload header disagrees. Brings parity
with PublisherTC->Parse and protects against future refactors that
might bypass _decode_tc_string_segments routing."
```

---

### Task 3: Document the single-return signature of `_parse_vendor_bitfield_or_range`

**Issue addressed:** Residual #3 — the new helper returns `$vendors_section` only, while the older `_parse_bitfield_or_range` returns `($vendors_section, $next_offset)`. The asymmetry is correct (each Disclosed/Allowed segment is its own decode unit, with no trailing payload to chain into), but a future maintainer might be confused. A short comment locks in the rationale.

**Files:**
- Modify: `lib/GDPR/IAB/TCFv2.pm:856` (just above the `_parse_vendor_bitfield_or_range` signature, after Task 2 lands)

**No test required:** comment-only change.

- [ ] **Step 1: Add the comment**

Edit `lib/GDPR/IAB/TCFv2.pm`, immediately above the `sub _parse_vendor_bitfield_or_range` line. Insert:

```perl
# Returns only $vendors_section — unlike _parse_bitfield_or_range, which
# yields ($section, $next_offset) so the caller can keep parsing the core
# segment.  Disclosed/Allowed Vendors live in their own base64 segment
# with nothing trailing the bitfield/range, so there is no offset to chain.
```

- [ ] **Step 2: Run the suite to confirm no accidental edit**

Run: `prove -lr t`

Expected: green.

- [ ] **Step 3: Commit**

```bash
git add lib/GDPR/IAB/TCFv2.pm
git commit -m "docs: explain single-return shape of vendor-segment helper"
```

---

### Task 4: Short-circuit `MaxVendorId == 0` in `_parse_vendor_bitfield_or_range`

**Issue addressed:** Residual #4 — the spec allows `MaxVendorId = 0` ("field unused"). The bitfield branch already handles it gracefully (empty slice, `contains` early-exits on `$id > max_id`). The range branch does NOT: `RangeSection->Parse` would happily try to read `num_entries` and any trailing range tuples even though, per spec, none should be present. This task short-circuits both branches to a uniform empty result before the sub-parsers run.

**Files:**
- Modify: `lib/GDPR/IAB/TCFv2.pm:856-...` (`_parse_vendor_bitfield_or_range`, post-Task-2 shape)
- Test: `t/05-tcf-v23.t`

- [ ] **Step 1: Write the failing test**

Append to `t/05-tcf-v23.t`:

```perl
subtest "MaxVendorId == 0 yields an empty vendor section" => sub {
    my $consent = GDPR::IAB::TCFv2->Parse(
        'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA'
    );

    # Hand-built Disclosed Vendors segment:
    #   segment_type = 001 (=1)
    #   max_vendor_id = 16 zero bits
    #   is_range_encoding = 1
    #   num_entries = 12 zero bits
    # Even with IsRange=1 and NumEntries=0, the helper must NOT call
    # RangeSection->Parse with max_id=0 (which would produce a section
    # whose contains() always returns false but whose presence still
    # passes parsing); it should short-circuit to an empty BitField.
    my $segment = '001' . ( '0' x 16 ) . '1' . ( '0' x 12 );

    my $section;
    lives_ok {
        $section = $consent->_parse_vendor_bitfield_or_range(
            $segment,
            GDPR::IAB::TCFv2::SEGMENT_TYPES->{DISCLOSED_VENDORS},
        );
    } 'max_id=0 segment parses without error';

    ok defined $section, 'returns a defined section';
    is $section->max_id, 0, 'max_id is 0';
    is $section->contains(1), undef,
        'contains(1) returns falsey (early-exit on id > max_id)';
};
```

- [ ] **Step 2: Run the new test**

Run: `prove -lv t/05-tcf-v23.t`

Expected: it should fail or pass *uncleanly*. If `RangeSection->Parse` is invoked with `max_id=0`, it may croak from the bounds-check inside `_parse_range`, or it may return successfully with no ranges. Note the actual behavior — the goal of Step 3 is to make the call deterministic by avoiding the sub-parser entirely.

- [ ] **Step 3: Add the short-circuit**

Edit `lib/GDPR/IAB/TCFv2.pm`. In `_parse_vendor_bitfield_or_range` (post-Task-2 shape), insert the short-circuit immediately after `$max_id` is read and before the `is_set` flag is consulted:

```perl
    my ( $max_id, $next_offset_after_max ) = get_uint16( $data, $offset );

    # Spec: MaxVendorId == 0 means "field unused".  Skip the IsRange flag
    # and any trailing payload entirely; return an empty BitField so that
    # has_vendor_disclosure() still reports the segment as present while
    # contains() always returns false for any vendor id.
    if ( $max_id == 0 ) {
        my ( $empty_section, ) = GDPR::IAB::TCFv2::BitField->Parse(
            data      => '',
            data_size => 0,
            max_id    => 0,
            options   => $self->{options},
        );
        return $empty_section;
    }

    my ( $is_range, $bf_offset ) = is_set( $data, $next_offset_after_max );

    # ... rest of the function unchanged
```

- [ ] **Step 4: Run the new test and the full suite**

Run: `prove -lv t/05-tcf-v23.t && prove -lr t`

Expected: new subtest PASS; full suite green.

- [ ] **Step 5: Run author tests**

Run: `prove -lr xt`

Expected: green. `make tidy` if needed; delete `.bak` files.

- [ ] **Step 6: Commit**

```bash
git add lib/GDPR/IAB/TCFv2.pm t/05-tcf-v23.t
git commit -m "fix: short-circuit MaxVendorId=0 in vendor-segment helper

Per IAB TCF v2 spec, MaxVendorId=0 means the field is unused.
Previously, a malformed segment with max_id=0 and IsRangeEncoding=1
would still call RangeSection->Parse and read NumEntries from the
trailing bits.  Now we return an empty BitField immediately,
preserving has_vendor_disclosure() semantics while making
contains() unconditionally false."
```

---

## Wrap-up

- [ ] **Final step: Update CHANGELOG and push for CI**

```bash
prove -lr t && prove -lr xt   # final green-light check
git push -u origin fix/vendor-segment-parser-cleanup
```

Then open a PR against `devel` (do NOT merge; the project owner handles merges per `AGENTS.md`).

Suggested PR body:

```markdown
## Vendor segment parser cleanup

Follow-up to #44.  Four small fixes that came out of the deep-dive
review of `_parse_vendor_bitfield_or_range`:

1. Align `data_size` in `_parse_bitfield` and `_parse_range_section`
   to slice length (cosmetic for valid input; tightens the size
   guard for truncated cores with small `max_id`).
2. Defensive segment-type assertion in `_parse_vendor_bitfield_or_range`
   (parity with `PublisherTC->Parse`).
3. Code comment explaining why the helper returns `$section` only,
   not `($section, $next_offset)`.
4. Short-circuit `MaxVendorId == 0` to an empty `BitField` so a
   malformed segment with `IsRangeEncoding=1` cannot cause spurious
   range parsing.

No public API changes.  All four are observable only through
new error messages and the new test cases in `t/05-tcf-v23.t`.
```

---

## Self-Review

**1. Spec coverage:**
- Issue 1 (slice-aligned `data_size` in core helpers) → Task 1 ✓
- Issue 2 (defensive segment-type check) → Task 2 ✓
- Issue 3 (comment about return signature) → Task 3 ✓
- Issue 4 (`max_id == 0` short-circuit) → Task 4 ✓

**2. Placeholder scan:**
- No "TODO", "TBD", or "fill in" instances. ✓
- Every code step shows the actual code. ✓
- Every command step shows the exact invocation and the expected outcome. ✓

**3. Type/symbol consistency:**
- `_parse_vendor_bitfield_or_range` signature evolves across Tasks 2 and 4: Task 2 introduces `$expected_segment_type` as the second positional arg; Task 4 inserts the `max_id == 0` short-circuit *after* the `get_uint16` line introduced in Task 2. Step 3 of Task 4 references this post-Task-2 shape explicitly. ✓
- `SEGMENT_TYPES->{DISCLOSED_VENDORS}` / `->{ALLOWED_VENDORS}` are the literal constants defined in `lib/GDPR/IAB/TCFv2.pm:39-44`. ✓
- The test cases in Task 2 and Task 4 call the private helper directly via `$consent->_parse_vendor_bitfield_or_range(...)`. The package fully-qualified constant access `GDPR::IAB::TCFv2::SEGMENT_TYPES->{...}` works because `SEGMENT_TYPES` is defined as a `use constant` and is accessible via fully-qualified name. ✓
- Variable rename in Task 2 (`$next_offset` → `$next_offset_after_max`) is preserved in Task 4's short-circuit insertion point. ✓
