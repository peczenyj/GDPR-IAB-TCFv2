# Validator Flexible-Purposes Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the validator's mixed-shape `flexible_purpose_ids` parameter with a flat int array whose default basis is **derived structurally** from membership in the existing `consent_purpose_ids` / `legitimate_interest_purpose_ids` lists, so the API mirrors the IAB GVL vendor-entry schema 1:1.

**Architecture:** `flexible_purpose_ids` becomes `ArrayRef[Int]`. The `_check_flexible_purposes` helper is removed. `_check_consent_purposes` and `_check_li_purposes` gain a single check: if a purpose appears in `flexible_purpose_ids`, dispatch through `is_vendor_allowed_for_flexible_purpose` with the appropriate default basis instead of through the strict-basis method. Construction-time coherence checks `croak` on incoherent inputs (a purpose listed in both `consent_purpose_ids` and `legitimate_interest_purpose_ids`, or a flexible purpose listed in neither). A bonus public function `from_gvl_vendor_entry` accepts a parsed GVL vendor entry hashref and returns a hash of constructor arguments, letting users feed GVL JSON straight in.

**Tech Stack:** Perl 5.008+, `Test::More`, `Test::Exception`, `Test::Warn`. No new dependencies.

**Operational note:** Per `AGENTS.md`, all work happens on a feature branch (`feat/phase-2-validator-v2`, the existing PR #54 branch). Do not commit to `devel`/`main`, do not merge into them, do not create tags. CI will re-run on each push to `feat/phase-2-validator-v2`. Test deps already declare `Test::Warn` (PR #49); no new `TEST_REQUIRES` needed.

**Style strictness reminder:** CI runs `xt/critic.t` (`Test::Perl::Critic`) and `xt/tidy.t` (`Test::PerlTidy`); they fail the build on violations. After non-trivial edits, run `make tidy && prove -lr xt`; delete the `.bak` files perltidy leaves behind (they're already excluded via `MANIFEST.SKIP`, but never stage them).

**Branch:** `feat/phase-2-validator-v2` (already exists; pushed to remote; PR #54 open against `devel`).

**Pre-flight (run before Task 1):**

```bash
git fetch origin
git checkout feat/phase-2-validator-v2
git pull --ff-only
perl Makefile.PL && make
prove -lr t          # baseline must be green: 8287 tests (post-review-fixups)
prove -lr xt         # baseline must be green: 41 tests (perlcritic + perltidy)
```

If baseline isn't green, stop and investigate.

---

## File Structure

| File | Role | Change |
|---|---|---|
| `lib/GDPR/IAB/TCFv2/Validator.pm` | The validator class | Modify: remove `_check_flexible_purposes`; teach `_check_consent_purposes` and `_check_li_purposes` to dispatch through `is_vendor_allowed_for_flexible_purpose` when a purpose is also in `flexible_purpose_ids`; add construction-time coherence checks; add `from_gvl_vendor_entry` public function; rewrite the POD `=item *` for `flexible_purpose_ids` and document `from_gvl_vendor_entry`. |
| `lib/GDPR/IAB/TCFv2/Validator/Result.pm` | Result object | No change. |
| `t/06-validator.t` | Validator tests | Modify: rewrite the two flexible-purpose subtests for the new shape; add coherence-check subtests; add `from_gvl_vendor_entry` subtest. |
| `MANIFEST` | Dist manifest | No change. |

Total new lines of code: ~60 (`from_gvl_vendor_entry` + coherence checks + POD). Total deleted: ~30 (the `_check_flexible_purposes` helper and its associated branching). Net change: small.

---

## Task 1: Remove `_check_flexible_purposes` and rewire consent/LI helpers

**Issue addressed:** Replace `flexible_purpose_ids` semantics. Today each entry can be a scalar or `{purpose_id, default_is_li}` hashref; this becomes a flat int array. The default basis is derived from which of `consent_purpose_ids` or `legitimate_interest_purpose_ids` the purpose ID appears in.

**Files:**
- Modify: `lib/GDPR/IAB/TCFv2/Validator.pm` — `_run_validation`, `_check_consent_purposes`, `_check_li_purposes`; remove `_check_flexible_purposes`
- Modify: `t/06-validator.t` — rewrite the two flexible-purpose subtests

- [ ] **Step 1: Read the current `_check_flexible_purposes` helper to confirm what's being removed**

```bash
grep -n -A 27 "^sub _check_flexible_purposes" lib/GDPR/IAB/TCFv2/Validator.pm
```

Expected: a 25-line subroutine that pops `purpose_id`/`default_is_li` from each entry of `flexible_purpose_ids` and calls `is_vendor_allowed_for_flexible_purpose`.

- [ ] **Step 2: Write the failing test for the new shape**

In `t/06-validator.t`, replace the two existing `flexible_purpose_ids - scalar form` and `flexible_purpose_ids - hashref form` subtests with:

```perl
subtest "flexible_purpose_ids derives default basis from membership" => sub {
    my $tc_string = 'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA';

    # Vendor 1, Purpose 6: consent=1, LI=1.  P6 is in consent_purpose_ids
    # AND flexible_purpose_ids → flexible with default consent.  Passes.
    my $v_consent_default = GDPR::IAB::TCFv2::Validator->new(
        vendor_id            => 1,
        consent_purpose_ids  => [6],
        flexible_purpose_ids => [6],
    );
    ok $v_consent_default->validate($tc_string),
      'flexible P6 with default consent (because P6 is in consent_purpose_ids) passes';

    # Vendor 2, Purpose 2: consent=0, LI=1.  P2 is in
    # legitimate_interest_purpose_ids AND flexible_purpose_ids → flexible
    # with default LI.  Passes (LI bit is set).
    my $v_li_default = GDPR::IAB::TCFv2::Validator->new(
        vendor_id                       => 2,
        legitimate_interest_purpose_ids => [2],
        flexible_purpose_ids            => [2],
    );
    ok $v_li_default->validate($tc_string),
      'flexible P2 with default LI (because P2 is in legitimate_interest_purpose_ids) passes';

    # P2 in consent_purpose_ids AND flexible_purpose_ids → default consent.
    # Vendor 2 has consent=0 for P2 → fails.
    my $v_p2_consent_flex = GDPR::IAB::TCFv2::Validator->new(
        vendor_id            => 2,
        consent_purpose_ids  => [2],
        flexible_purpose_ids => [2],
    );
    ok !$v_p2_consent_flex->validate($tc_string),
      'flexible P2 with default consent fails for vendor 2 (no consent bit)';
};
```

- [ ] **Step 3: Run the test, confirm it fails**

```bash
prove -lv t/06-validator.t
```

Expected: subtest `flexible_purpose_ids derives default basis from membership` fails, because the existing implementation expects `flexible_purpose_ids` entries to be either scalars (with implicit `default_is_li=0`) or hashrefs (with explicit `default_is_li`). The new shape — same purpose ID in both `consent_purpose_ids` and `flexible_purpose_ids` — currently produces a "purpose 6 not allowed for purpose 6 (consent)"-style failure for the consent-default case, or success-by-accident for the LI-default case. The exact failure messages don't matter; what matters is that the new behaviour we're testing for isn't yet implemented.

- [ ] **Step 4: Modify `_check_consent_purposes` and `_check_li_purposes` to dispatch through the flexible helper when applicable**

Replace `lib/GDPR/IAB/TCFv2/Validator.pm:100-134` (the `_check_consent_purposes` and `_check_li_purposes` subs) with:

```perl
sub _check_consent_purposes {
    my ( $self, $tc, $vendor_id, $strict, $reasons, $stop_on_first ) = @_;

    foreach my $pid ( @{ $self->{consent_purpose_ids} } ) {
        my $allowed =
          $self->{_flexible_set}->{$pid}
          ? $tc->is_vendor_allowed_for_flexible_purpose(
            $vendor_id, $pid, 0, strict => $strict
          )
          : $tc->is_vendor_consent_allowed(
            $vendor_id, $pid, strict => $strict
          );

        unless ($allowed) {
            push @{$reasons},
              "vendor $vendor_id not allowed for purpose $pid (consent)";
            return if $stop_on_first;
        }
    }
    return;
}

sub _check_li_purposes {
    my ( $self, $tc, $vendor_id, $strict, $reasons, $stop_on_first ) = @_;

    foreach my $pid ( @{ $self->{legitimate_interest_purpose_ids} } ) {
        my $allowed =
          $self->{_flexible_set}->{$pid}
          ? $tc->is_vendor_allowed_for_flexible_purpose(
            $vendor_id, $pid, 1, strict => $strict
          )
          : $tc->is_vendor_legitimate_interest_allowed(
            $vendor_id, $pid, strict => $strict
          );

        unless ($allowed) {
            push @{$reasons},
              "vendor $vendor_id not allowed for purpose $pid (legitimate interest)";
            return if $stop_on_first;
        }
    }
    return;
}
```

The `$self->{_flexible_set}` is a hashref-as-set (`{ 2 => 1, 7 => 1 }`) built once at construction time for O(1) membership lookup; we'll add it in Task 2.

- [ ] **Step 5: Remove the standalone `_check_flexible_purposes` helper**

In `lib/GDPR/IAB/TCFv2/Validator.pm`, delete the entire `sub _check_flexible_purposes { ... }` block (was lines 136-162 before edits; locate it with `grep -n '^sub _check_flexible_purposes' lib/GDPR/IAB/TCFv2/Validator.pm`).

- [ ] **Step 6: Remove the call to `_check_flexible_purposes` from `_run_validation`**

In `lib/GDPR/IAB/TCFv2/Validator.pm`, find this block in `_run_validation`:

```perl
    $self->_check_flexible_purposes(
        $tc, $vendor_id, $strict, \@reasons,
        $stop_on_first
    );
```

…and delete it. The four lines before it (the `_check_li_purposes` call + its short-circuit `return`) remain unchanged.

- [ ] **Step 7: Build the `_flexible_set` lookup in the constructor**

In `lib/GDPR/IAB/TCFv2/Validator.pm`, modify `sub new` (currently lines 10-24). Replace it with:

```perl
sub new {
    my ( $klass, %args ) = @_;

    my $consent             = $args{consent_purpose_ids}             || [];
    my $legitimate_interest = $args{legitimate_interest_purpose_ids} || [];
    my $flexible            = $args{flexible_purpose_ids}            || [];

    my $self = {
        vendor_id                       => $args{vendor_id},
        consent_purpose_ids             => $consent,
        legitimate_interest_purpose_ids => $legitimate_interest,
        flexible_purpose_ids            => $flexible,
        _flexible_set                   => { map { $_ => 1 } @{$flexible} },
        check_disclosed_vendors         => $args{check_disclosed_vendors} || 0,
        strict                  => exists $args{strict} ? $args{strict} : 0,
    };

    return bless $self, $klass;
}
```

`_flexible_set` is a private (underscore-prefixed) cache used by `_check_consent_purposes` / `_check_li_purposes`. Storing as a hash makes per-purpose lookup O(1).

- [ ] **Step 8: Run the suite + xt**

```bash
prove -lv t/06-validator.t
prove -lr t
prove -lr xt
```

Expected: all three commands green. The new subtest from Step 2 passes; xt passes (no critic/tidy regressions yet — but if perltidy reformats the new code, follow up with `make tidy` and re-run `prove -lr xt` until clean; remove any `.bak` files produced).

- [ ] **Step 9: Commit**

```bash
git add lib/GDPR/IAB/TCFv2/Validator.pm t/06-validator.t
git commit -m "refactor(validator): derive flexible-purpose default basis from membership

flexible_purpose_ids is now a flat ArrayRef[Int].  The default
legal basis for each flexible purpose is derived structurally:

  * Purpose in consent_purpose_ids   AND flexible_purpose_ids
        -> flexible with default consent
  * Purpose in legitimate_interest_purpose_ids AND flexible_purpose_ids
        -> flexible with default legitimate interest

This mirrors the IAB GVL vendor-entry schema 1:1 (purposes /
legIntPurposes / flexiblePurposes) and removes the mixed-shape
parameter that accepted both scalars and {purpose_id, default_is_li}
hashrefs."
```

---

## Task 2: Add construction-time coherence checks

**Issue addressed:** With the new shape, two configurations are structurally incoherent and should `croak` at construction time rather than producing surprising results at validation time:

1. A purpose appearing in **both** `consent_purpose_ids` and `legitimate_interest_purpose_ids` (a vendor cannot declare the same purpose under both bases per the GVL schema).
2. A purpose in `flexible_purpose_ids` that appears in **neither** `consent_purpose_ids` nor `legitimate_interest_purpose_ids` (no default basis can be derived).

**Files:**
- Modify: `lib/GDPR/IAB/TCFv2/Validator.pm` — `sub new`
- Modify: `t/06-validator.t` — add coherence subtest

- [ ] **Step 1: Write the failing test**

Append to `t/06-validator.t`:

```perl
subtest "Validator coherence checks at construction time" => sub {

    # A purpose can't be in both consent_purpose_ids and
    # legitimate_interest_purpose_ids — the GVL schema treats those as
    # mutually exclusive declarations.
    throws_ok {
        GDPR::IAB::TCFv2::Validator->new(
            vendor_id                       => 1,
            consent_purpose_ids             => [3],
            legitimate_interest_purpose_ids => [3],
        );
    }
    qr/purpose 3 cannot be in both consent_purpose_ids and legitimate_interest_purpose_ids/,
      'croaks when a purpose is listed under both bases';

    # A flexible purpose must be listed under one of the two bases —
    # otherwise no default can be derived.
    throws_ok {
        GDPR::IAB::TCFv2::Validator->new(
            vendor_id            => 1,
            flexible_purpose_ids => [5],
        );
    }
    qr/flexible purpose 5 must also appear in consent_purpose_ids or legitimate_interest_purpose_ids/,
      'croaks when a flexible purpose has no derivable default basis';

    # Sanity: a properly-coherent config still constructs.
    lives_ok {
        GDPR::IAB::TCFv2::Validator->new(
            vendor_id                       => 1,
            consent_purpose_ids             => [ 1, 6 ],
            legitimate_interest_purpose_ids => [ 2, 10 ],
            flexible_purpose_ids            => [ 6, 2 ],
        );
    }
    'coherent configuration constructs without error';
};
```

- [ ] **Step 2: Run the test, confirm it fails**

```bash
prove -lv t/06-validator.t
```

Expected: the new subtest's `throws_ok` assertions fail because the constructor does not currently `croak` on these configurations.

- [ ] **Step 3: Add the coherence checks to the constructor**

In `lib/GDPR/IAB/TCFv2/Validator.pm`, modify `sub new` to call a new private helper before blessing. Replace the body of `sub new` with:

```perl
sub new {
    my ( $klass, %args ) = @_;

    my $consent             = $args{consent_purpose_ids}             || [];
    my $legitimate_interest = $args{legitimate_interest_purpose_ids} || [];
    my $flexible            = $args{flexible_purpose_ids}            || [];

    _check_coherence( $consent, $legitimate_interest, $flexible );

    my $self = {
        vendor_id                       => $args{vendor_id},
        consent_purpose_ids             => $consent,
        legitimate_interest_purpose_ids => $legitimate_interest,
        flexible_purpose_ids            => $flexible,
        _flexible_set                   => { map { $_ => 1 } @{$flexible} },
        check_disclosed_vendors         => $args{check_disclosed_vendors} || 0,
        strict                  => exists $args{strict} ? $args{strict} : 0,
    };

    return bless $self, $klass;
}

sub _check_coherence {
    my ( $consent, $legitimate_interest, $flexible ) = @_;

    my %consent_set = map { $_ => 1 } @{$consent};
    my %li_set      = map { $_ => 1 } @{$legitimate_interest};

    foreach my $pid ( @{$consent} ) {
        croak
          "purpose $pid cannot be in both consent_purpose_ids and legitimate_interest_purpose_ids"
          if $li_set{$pid};
    }

    foreach my $pid ( @{$flexible} ) {
        next if $consent_set{$pid} || $li_set{$pid};
        croak
          "flexible purpose $pid must also appear in consent_purpose_ids or legitimate_interest_purpose_ids";
    }

    return;
}
```

`_check_coherence` is a plain function (not a method) — easier to test in isolation, no `$self` to pass around since the constructor hasn't blessed yet.

- [ ] **Step 4: Run the suite + xt**

```bash
prove -lv t/06-validator.t
prove -lr t
prove -lr xt
```

Expected: all green. If perltidy complains, run `make tidy` and re-stage; remove the `.bak` files.

- [ ] **Step 5: Commit**

```bash
git add lib/GDPR/IAB/TCFv2/Validator.pm t/06-validator.t
git commit -m "feat(validator): croak on incoherent purpose-list configurations

Two configurations are now caught at construction time rather than
silently producing strange validation outcomes:

  1. A purpose listed in both consent_purpose_ids and
     legitimate_interest_purpose_ids (GVL semantics treat those
     as mutually exclusive vendor declarations).
  2. A purpose listed in flexible_purpose_ids but neither of the
     other two lists (no default basis can be derived).

Both croak with explicit messages naming the offending purpose ID."
```

---

## Task 3: Add the public `from_gvl_vendor_entry` function

**Issue addressed:** Bonus convenience for users who have parsed GVL JSON. `from_gvl_vendor_entry` accepts a single vendor-entry hashref (per the IAB GVL schema) and returns a hash of constructor arguments suitable for splatting into `Validator->new`.

**Files:**
- Modify: `lib/GDPR/IAB/TCFv2/Validator.pm` — add `from_gvl_vendor_entry`
- Modify: `t/06-validator.t` — add subtest covering the function

**Design note:** This is a plain function on the package, not a constructor. It returns the *arguments* `Validator->new` needs, so users can mix in extra keys (`check_disclosed_vendors`, `strict`) without conflicting with the GVL data:

```perl
my %args = GDPR::IAB::TCFv2::Validator::from_gvl_vendor_entry($vendor_entry);
my $v = GDPR::IAB::TCFv2::Validator->new( %args, strict => 1 );
```

This is consistent with Perl's `wantarray`-on-list-context idiom and keeps the constructor a single entry point.

- [ ] **Step 1: Write the failing test**

Append to `t/06-validator.t`:

```perl
subtest "from_gvl_vendor_entry maps GVL JSON to constructor args" => sub {
    my $entry = {
        id               => 284,
        name             => 'Weborama',                       # ignored
        purposes         => [ 1, 3, 4, 5, 6 ],
        legIntPurposes   => [ 2, 7, 8, 9, 10, 11 ],
        flexiblePurposes => [ 2, 7, 8, 9, 10, 11 ],
    };

    my %args = GDPR::IAB::TCFv2::Validator::from_gvl_vendor_entry($entry);

    is $args{vendor_id}, 284, 'vendor_id maps from id';
    is_deeply $args{consent_purpose_ids},
      [ 1, 3, 4, 5, 6 ],
      'consent_purpose_ids maps from purposes';
    is_deeply $args{legitimate_interest_purpose_ids},
      [ 2, 7, 8, 9, 10, 11 ],
      'legitimate_interest_purpose_ids maps from legIntPurposes';
    is_deeply $args{flexible_purpose_ids},
      [ 2, 7, 8, 9, 10, 11 ],
      'flexible_purpose_ids maps from flexiblePurposes';

    # Returned args splat into the constructor cleanly, mixed with extras.
    my $v = GDPR::IAB::TCFv2::Validator->new( %args, strict => 1 );
    isa_ok $v, 'GDPR::IAB::TCFv2::Validator';

    # Croak on missing id
    throws_ok {
        GDPR::IAB::TCFv2::Validator::from_gvl_vendor_entry(
            {   purposes         => [],
                legIntPurposes   => [],
                flexiblePurposes => [],
            }
        );
    }
    qr/from_gvl_vendor_entry: missing 'id'/,
      'croaks on a vendor entry missing the id field';

    # Missing list fields default to empty arrayrefs (a vendor with no
    # legIntPurposes is valid in the GVL schema).
    my %sparse = GDPR::IAB::TCFv2::Validator::from_gvl_vendor_entry(
        { id => 1 } );
    is_deeply $sparse{consent_purpose_ids},             [],
      'missing purposes defaults to empty arrayref';
    is_deeply $sparse{legitimate_interest_purpose_ids}, [],
      'missing legIntPurposes defaults to empty arrayref';
    is_deeply $sparse{flexible_purpose_ids},            [],
      'missing flexiblePurposes defaults to empty arrayref';
};
```

- [ ] **Step 2: Run the test, confirm it fails**

```bash
prove -lv t/06-validator.t
```

Expected: subtest `from_gvl_vendor_entry maps GVL JSON to constructor args` fails with `Undefined subroutine &GDPR::IAB::TCFv2::Validator::from_gvl_vendor_entry`.

- [ ] **Step 3: Implement `from_gvl_vendor_entry`**

In `lib/GDPR/IAB/TCFv2/Validator.pm`, add this subroutine immediately after `sub _check_coherence` and before `sub validate`:

```perl
sub from_gvl_vendor_entry {
    my ($entry) = @_;

    croak "from_gvl_vendor_entry: missing 'id' in vendor entry"
      unless defined $entry->{id};

    return (
        vendor_id                       => $entry->{id},
        consent_purpose_ids             => $entry->{purposes}         || [],
        legitimate_interest_purpose_ids => $entry->{legIntPurposes}   || [],
        flexible_purpose_ids            => $entry->{flexiblePurposes} || [],
    );
}
```

This is intentionally:

- A **plain function** (no `$self`), invoked as `GDPR::IAB::TCFv2::Validator::from_gvl_vendor_entry($entry)`.
- Returns a **list of key-value pairs** suitable for splatting into `Validator->new(%args, ...extras)`.
- Ignores other GVL fields (`name`, `purposeName`, `policyUrl`, `cookieMaxAgeSeconds`, etc.) — they're not relevant to validation.
- Croaks only on missing `id`. Other fields default to empty arrayrefs because the GVL schema permits a vendor to have no legitimate-interest or flexible purposes.

- [ ] **Step 4: Run the suite + xt**

```bash
prove -lv t/06-validator.t
prove -lr t
prove -lr xt
```

Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add lib/GDPR/IAB/TCFv2/Validator.pm t/06-validator.t
git commit -m "feat(validator): add from_gvl_vendor_entry helper

Maps a parsed IAB GVL vendor entry hashref to the constructor
arguments Validator->new expects.  Field aliases:

  id               -> vendor_id
  purposes         -> consent_purpose_ids
  legIntPurposes   -> legitimate_interest_purpose_ids
  flexiblePurposes -> flexible_purpose_ids

Returns a list (key-value pairs) so callers can splat into the
constructor and add extras:

  my \$v = GDPR::IAB::TCFv2::Validator->new(
      GDPR::IAB::TCFv2::Validator::from_gvl_vendor_entry(\$entry),
      strict => 1,
  );

Croaks only on missing 'id'.  Missing list fields default to
empty arrayrefs per the GVL schema (a vendor may legitimately
have no LI or flexible purposes)."
```

---

## Task 4: Update POD to reflect the new design

**Issue addressed:** The Validator's POD (added in PR #54's review fixups) describes the old shape — scalar-or-hashref `flexible_purpose_ids` with `default_is_li`. Needs updating to match the new structural-derivation design and to document `from_gvl_vendor_entry`.

**Files:**
- Modify: `lib/GDPR/IAB/TCFv2/Validator.pm` — POD section

- [ ] **Step 1: Locate the relevant POD section**

```bash
grep -n '=item \*\|=head' lib/GDPR/IAB/TCFv2/Validator.pm | tail -30
```

Expected: a list of `=item *` and `=head*` markers covering CONSTRUCTOR, METHODS, SEE ALSO. The relevant `=item *` is the one that begins with `C<flexible_purpose_ids>`.

- [ ] **Step 2: Rewrite the `flexible_purpose_ids` POD entry**

In `lib/GDPR/IAB/TCFv2/Validator.pm`, find the `=item *` block describing `flexible_purpose_ids` (it documents the old scalar-or-hashref shape). Replace it with:

```pod
=item *

C<flexible_purpose_ids> — arrayref of purpose IDs that are B<flexible> per the
vendor's GVL declaration (the basis can flip if a publisher restriction is
present in the TC string). The default basis is derived structurally:

=over 8

=item *

If the purpose ID also appears in C<consent_purpose_ids>, the default basis
is consent.

=item *

If the purpose ID also appears in C<legitimate_interest_purpose_ids>, the
default basis is legitimate interest.

=back

A purpose listed in C<flexible_purpose_ids> must also appear in exactly one
of the other two lists, or the constructor C<croak>s. Validated via
L<GDPR::IAB::TCFv2/is_vendor_allowed_for_flexible_purpose>.
```

- [ ] **Step 3: Add a POD entry for `from_gvl_vendor_entry`**

In the same file, immediately before `=head1 SEE ALSO`, add this section:

```pod
=head1 FUNCTIONS

=head2 from_gvl_vendor_entry

    my %args = GDPR::IAB::TCFv2::Validator::from_gvl_vendor_entry($vendor_entry);
    my $validator = GDPR::IAB::TCFv2::Validator->new( %args, strict => 1 );

Maps a parsed IAB Global Vendor List vendor-entry hashref to the constructor
arguments L</new> expects. Field aliases:

=over 4

=item *

C<id> ⟶ C<vendor_id>

=item *

C<purposes> ⟶ C<consent_purpose_ids>

=item *

C<legIntPurposes> ⟶ C<legitimate_interest_purpose_ids>

=item *

C<flexiblePurposes> ⟶ C<flexible_purpose_ids>

=back

Returns a list (key-value pairs), so callers can splat into the constructor
alongside additional keys like C<strict> and C<check_disclosed_vendors>.
Other fields on the vendor entry (C<name>, C<policyUrl>, etc.) are ignored —
they aren't relevant to validation.

C<croak>s only when C<id> is missing. Missing list fields default to empty
arrayrefs, since the GVL schema permits a vendor to declare no
legitimate-interest or flexible purposes.
```

- [ ] **Step 4: Update the SYNOPSIS to use the new shape**

Find the `SYNOPSIS` block in `lib/GDPR/IAB/TCFv2/Validator.pm` and replace the `flexible_purpose_ids` line to use the new flat-int form. The block currently reads:

```pod
        flexible_purpose_ids            => [
            { purpose_id => 2, default_is_li => 1 },
        ],
```

Replace with:

```pod
        flexible_purpose_ids            => [ 2 ],
```

(Reflecting that purpose 2 is in `legitimate_interest_purpose_ids` and is also flexible, with default LI derived from membership.)

- [ ] **Step 5: Verify POD is well-formed**

```bash
podchecker lib/GDPR/IAB/TCFv2/Validator.pm
```

Expected: `lib/GDPR/IAB/TCFv2/Validator.pm pod syntax OK.`

- [ ] **Step 6: Run the full suite + xt**

```bash
prove -lr t
prove -lr xt
```

Expected: all green. POD-only changes shouldn't affect tests, but the POD test (`t/99-pod.t`) verifies syntactic well-formedness.

- [ ] **Step 7: Commit**

```bash
git add lib/GDPR/IAB/TCFv2/Validator.pm
git commit -m "docs(validator): rewrite flexible_purpose_ids POD for the new shape

Document the structural derivation of default basis (membership in
consent_purpose_ids vs legitimate_interest_purpose_ids), the
construction-time coherence checks that croak on incoherent inputs,
and the new from_gvl_vendor_entry public function in a new
=head1 FUNCTIONS section.  SYNOPSIS updated to use the flat-int
flexible_purpose_ids shape."
```

---

## Wrap-up

- [ ] **Final step: Update PR #54 description**

```bash
prove -lr t && prove -lr xt   # final green-light check (8290 tests, +3 from this plan)
git push origin feat/phase-2-validator-v2
```

Then update the PR body via `gh api` (the `gh pr edit --body-file` path hits a known GraphQL deprecation; use REST):

```bash
cat > /tmp/pr54_body.md <<'PRBODY'
... existing PR body content ...

## Update: flexible_purpose_ids redesign

The mixed-shape `flexible_purpose_ids` parameter has been replaced with a
flat ArrayRef[Int]. The default legal basis for each flexible purpose is now
derived structurally from membership in `consent_purpose_ids` (default
consent) or `legitimate_interest_purpose_ids` (default LI), mirroring the
IAB GVL vendor-entry schema 1:1.

Construction-time coherence checks `croak` on:

  * a purpose listed under both bases (mutually exclusive per GVL)
  * a flexible purpose with no derivable default

A new public function `from_gvl_vendor_entry` aliases parsed GVL JSON
fields to the constructor's argument names, letting callers plug a parsed
GVL entry straight in.
PRBODY

jq -Rs '{body: .}' < /tmp/pr54_body.md > /tmp/pr54_payload.json
gh api -X PATCH repos/peczenyj/GDPR-IAB-TCFv2/pulls/54 --input /tmp/pr54_payload.json --jq '.title'
```

(Adapt the actual body content; this is a sketch of the additions, not the full replacement.)

The PR title can stay as is or be retitled to `Phase 2: The Validator Interface (rebased + reviewed + GVL-aligned shape)` — your call.

---

## Self-Review

**1. Spec coverage:**
- Concept of flexible-purpose default basis derivation → Task 1 ✓
- Construction-time coherence enforcement → Task 2 ✓
- GVL-vendor-entry conversion helper → Task 3 ✓
- POD updates for new shape → Task 4 ✓

**2. Placeholder scan:**
- No "TODO", "TBD", or "fill in" instances. ✓
- Every code step shows actual code. ✓
- Every command shows the exact invocation and the expected outcome. ✓

**3. Type/symbol consistency:**
- `_flexible_set` is introduced in Task 1 Step 7 (constructor) and consumed in Task 1 Step 4 (helpers). It's a hashref with integer keys mapping to truthy values; lookup is `$self->{_flexible_set}->{$pid}`. ✓
- `_check_coherence` is introduced in Task 2 Step 3 as a plain (non-method) sub. Called from `sub new` BEFORE the `bless`, so passing `($consent, $legitimate_interest, $flexible)` rather than `$self`. ✓
- `from_gvl_vendor_entry` is introduced in Task 3 Step 3 as a plain (non-method) sub returning a list. ✓
- The constructor in Task 2 Step 3 already includes the `_flexible_set` line from Task 1 Step 7 — these are sequential edits to the same `sub new`, and Task 2 supersedes Task 1's version. ✓

**4. Risk register:**
- *perltidy will likely reformat the new `_check_coherence` sub.* Mitigation: `make tidy && prove -lr xt` is part of every task's verification step.
- *Existing tests in t/06-validator.t that pass `flexible_purpose_ids` in the old shape will break.* Mitigation: Task 1 Step 2 explicitly replaces the two old subtests; the rest of the file uses only `consent_purpose_ids` / `legitimate_interest_purpose_ids` and is unaffected.
- *PR #54 already shipped a 145-line POD for Validator.pm.* Task 4 modifies only one `=item *` and adds a `=head1 FUNCTIONS` section; the rest of the POD is untouched.
