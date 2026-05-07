use strict;
use warnings;
use Test::More;
use FindBin;
use File::Spec;
use lib 'lib';

use GDPR::IAB::TCFv2::Validator;
use GDPR::IAB::TCFv2::Validator::Failure;
use GDPR::IAB::TCFv2::Validator::Reason qw<:all>;

# A known-valid TC string from elsewhere in the test suite. CMP id 21,
# vendor consents include 32. Used as the baseline for failure-injecting
# variations below.
my $tc_string =
  'CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA';

subtest 'Validator::Failure: round-trip and stringification' => sub {
    my $f = GDPR::IAB::TCFv2::Validator::Failure->new(
        code             => ReasonPublisherRestrictionNotAllowed,
        message          => "publisher restriction: not allowed (purpose 5)",
        purpose_id       => 5,
        vendor_id        => 284,
        restriction_type => 0,
    );

    is( $f->code, ReasonPublisherRestrictionNotAllowed, 'code accessor' );
    is( $f->message, "publisher restriction: not allowed (purpose 5)",
        'message accessor'
    );
    is( $f->purpose_id,       5,     'purpose_id accessor' );
    is( $f->vendor_id,        284,   'vendor_id accessor' );
    is( $f->restriction_type, 0,     'restriction_type accessor' );
    is( $f->cmp_id,           undef, 'cmp_id is undef when not set' );

    is( "$f", "publisher restriction: not allowed (purpose 5)",
        'stringification returns message'
    );
};

subtest 'Validator::Failure: unset structured fields are undef' => sub {
    my $f = GDPR::IAB::TCFv2::Validator::Failure->new(
        code    => ReasonVendorNotAllowed,
        message => "vendor not allowed",
    );

    is( $f->purpose_id,       undef, 'purpose_id defaults to undef' );
    is( $f->vendor_id,        undef, 'vendor_id defaults to undef' );
    is( $f->restriction_type, undef, 'restriction_type defaults to undef' );
    is( $f->cmp_id,           undef, 'cmp_id defaults to undef' );
};

subtest 'Validator::Result: passing result has no failures' => sub {
    my $validator = GDPR::IAB::TCFv2::Validator->new( vendor_id => 32 );
    my $result    = $validator->validate($tc_string);

    ok( $result,           'result is truthy when validation passes' );
    ok( $result->is_valid, 'is_valid is true when validation passes' );

    my @failures = $result->failures;
    is( scalar @failures, 0, 'no failures on a passing result' );

    my @codes = $result->reason_codes;
    is( scalar @codes, 0, 'no reason codes on a passing result' );

    my @reasons = $result->reasons;
    is( scalar @reasons, 0, 'no reason strings on a passing result' );

    is( "$result", '', 'stringifies to empty on success' );
};

subtest
  'Validator::Result: failing result exposes failures + codes + reasons' =>
  sub {

    # Vendor 99999 is well above any vendor in the fixture, so
    # consent for any required purpose will fail. Forces predictable
    # ReasonVendorNotAllowedConsent failures.
    my $validator = GDPR::IAB::TCFv2::Validator->new(
        vendor_id           => 99999,
        consent_purpose_ids => [ 1, 3 ],
    );
    my $result = $validator->validate_all($tc_string);

    ok( !$result,           'result is falsy on failure' );
    ok( !$result->is_valid, 'is_valid is false on failure' );

    my @failures = $result->failures;
    cmp_ok( scalar @failures, '>=', 1, 'at least one failure recorded' );

    isa_ok $failures[0], 'GDPR::IAB::TCFv2::Validator::Failure',
      'each entry is a Failure object';

    my @codes   = $result->reason_codes;
    my @reasons = $result->reasons;
    is( scalar @codes,   scalar @failures, 'reason_codes count matches' );
    is( scalar @reasons, scalar @failures, 'reasons count matches' );

    # All consent-purpose failures should carry the consent code and
    # the offending vendor + purpose ids.
    for my $f (@failures) {
        is( $f->code, ReasonVendorNotAllowedConsent,
            'consent-path failures use ReasonVendorNotAllowedConsent'
        );
        is( $f->vendor_id, 99999, 'vendor_id is set on the failure' );
        ok( defined $f->purpose_id, 'purpose_id is set on the failure' );
    }

    # Stringified result is the failure messages joined per the
    # output-record-separator overload (legacy contract).
    like(
        "$result", qr/vendor 99999 not allowed for purpose/,
        'stringification includes failure messages'
    );
  };

subtest
  'Validator::Result: min_policy_version failure carries correct code' => sub {

    # The fixture TC string uses TCF policy version 2 (pre v2.3).
    # A floor of 5 forces a ReasonPolicyVersionTooLow failure on the
    # first rule, before any vendor/purpose check.
    my $validator = GDPR::IAB::TCFv2::Validator->new(
        vendor_id          => 32,
        min_policy_version => 5,
    );
    my $result = $validator->validate($tc_string);

    ok( !$result, 'result is falsy when policy version is too low' );

    my @failures = $result->failures;
    is( scalar @failures, 1, 'fail-fast yields exactly one failure' );

    is( $failures[0]->code, ReasonPolicyVersionTooLow,
        'code is ReasonPolicyVersionTooLow'
    );
    like(
        $failures[0]->message,
        qr/policy version \d+ is below required minimum 5/,
        'message describes the policy-version mismatch'
    );
  };

subtest
  'Validator::Result: P1 LI carve-out emits ReasonLegitimateInterestNotPermittedForPurpose'
  => sub {

    # Policy version 2 fixture; vendor 1 has the LI bit but the spec
    # forbids LI for Purpose 1 regardless of the bit. The validator
    # detects this *before* delegating to the parser, so the failure
    # carries the carve-out code and not the generic LI vendor code.
    my $validator = GDPR::IAB::TCFv2::Validator->new(
        vendor_id                       => 1,
        legitimate_interest_purpose_ids => [1],
    );
    my $result = $validator->validate($tc_string);

    ok( !$result, 'P1 LI is rejected at any policy version' );

    my @failures = $result->failures;
    is( scalar @failures, 1, 'fail-fast yields exactly one failure' );

    is( $failures[0]->code, ReasonLegitimateInterestNotPermittedForPurpose,
        'code is ReasonLegitimateInterestNotPermittedForPurpose'
    );
    is( $failures[0]->purpose_id, 1, 'purpose_id is 1' );
    is( $failures[0]->vendor_id,  1, 'vendor_id is set on the failure' );
    is( $failures[0]->message,
        'legitimate interest not permitted for purpose 1',
        'message describes the carve-out'
    );
  };

subtest
  'Validator::Result: P3 LI carve-out only fires on TCF v2.2+ (policy >= 4)'
  => sub {

    # Policy version 5 fixture (TCF v2.2+). Vendor 32 has both consent
    # and LI bits, but the spec forbids LI for Purposes 3-6 at this
    # policy version regardless of the bit.
    my $tc_v22 =
      'CP188cAQKFpAAAHABBENBSFsAP_gAEPgAAiQKqNX_H__bW9r8X73aft0eY1P9_j77uQxBhfJE-4FzLvW_JwXx2ExNA36tqIKmRIEu3bBIQNlHJHUTVigaogVryHMak2cpTNKJ6BkiFMRM2dYCF5vm4tj-QKY5_r993dx2D-t_dv83dzyz81Hn3f5_2e0eLCdQ5-tDfv9bROb-9IPd_78v4v8_l_rk2_eT1n_tevr7D_-ft8__XW_9_fff_9Pn_-uB_-_3_vf_EFUwCTDQqIA-wJCQg0DCKBACoKwgIoFAQAAJA0QEAJgwKdgYALrCRACAFAAMEAIAAQZAAgAAAgAQiACQAoEAAEAgUAAYAEAwEABAwAAgAsBAIAAQHQMUwIIFAsIEjMioUwIQoEggJbKhBICgQVwhCLPAIgERMFAAgAAAVgACAsFgcSSAlQkECXUG0AABAAgFEIFQgk9MAAwJmy1B4MG0ZWmAYPmCRDTAMgCIIyEAAAA.f_wACHwAAAAA';

    my $validator_v22 = GDPR::IAB::TCFv2::Validator->new(
        vendor_id                       => 32,
        legitimate_interest_purpose_ids => [3],
    );
    my $result_v22 = $validator_v22->validate($tc_v22);

    ok( !$result_v22, 'P3 LI rejected at policy 5' );
    my @f22 = $result_v22->failures;
    is( $f22[0]->code, ReasonLegitimateInterestNotPermittedForPurpose,
        'P3 at policy 5 → carve-out reason'
    );
    is( $f22[0]->purpose_id, 3, 'purpose_id is 3' );

    # Same purpose ID against the policy-2 fixture: carve-out does NOT
    # apply (P3-6 carve-out only kicks in at policy >= 4). Vendor 1 has
    # both purpose 3 LI and vendor LI in this fixture, so this should
    # actually pass — confirming the carve-out is policy-version gated.
    my $validator_v20 = GDPR::IAB::TCFv2::Validator->new(
        vendor_id                       => 1,
        legitimate_interest_purpose_ids => [3],
    );
    my $result_v20 = $validator_v20->validate($tc_string);

    ok( $result_v20, 'P3 LI passes at policy 2 (carve-out does not apply)' );
  };

subtest 'Validator::Result: invalid CMP carries ReasonInvalidCMP' => sub {
    require GDPR::IAB::TCFv2::CMPValidator;

    my $cmp_file = File::Spec->catfile(
        $FindBin::Bin, 'corpus',
        'cmp-list.json'
    );

    # CMP 888 is not in the fixture; this TC string carries it.
    my $tc_unknown_cmp =
      'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA';

    my $validator = GDPR::IAB::TCFv2::Validator->new(
        vendor_id     => 1,
        cmp_validator => { file => $cmp_file, now => 1776254400 },
    );
    my $result = $validator->validate($tc_unknown_cmp);

    ok( !$result, 'unknown CMP fails validation' );

    my @failures = $result->failures;
    is( scalar @failures, 1, 'fail-fast yields exactly one failure' );

    is( $failures[0]->code, ReasonInvalidCMP,
        'code is ReasonInvalidCMP'
    );
    is( $failures[0]->cmp_id, 888,
        'cmp_id is set to the CMP from the consent string'
    );
};

done_testing;
