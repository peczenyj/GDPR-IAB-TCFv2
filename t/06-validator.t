use strict;
use warnings;

use Test::More;
use Test::Exception;
use Test::Warn;

use GDPR::IAB::TCFv2;
use GDPR::IAB::TCFv2::Validator;
use GDPR::IAB::TCFv2::Constants::Purpose qw<:all>;

subtest "Validator basic usage" => sub {
    my $tc_string = 'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA';

    my $validator = GDPR::IAB::TCFv2::Validator->new(
        vendor_id           => 1,
        consent_purpose_ids => [6],    # Allowed
    );

    my $result = $validator->validate($tc_string);
    ok $result, 'validation should pass';
    is $result->is_valid, 1, 'is_valid should be 1';
    is "$result", '', 'stringification should be empty for valid result';
};

subtest "Validator failures" => sub {
    my $tc_string = 'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA';

    my $validator = GDPR::IAB::TCFv2::Validator->new(
        vendor_id           => 1,
        consent_purpose_ids => [ 1, 6 ],    # 1 is missing consent bit, 6 is OK
    );

    subtest "validate (first failure)" => sub {
        my $result = $validator->validate($tc_string);
        ok !$result, 'validation should fail';
        is scalar( $result->reasons ), 1, 'should have 1 reason';
        like "$result", qr/not allowed for purpose 1/,
          'should have correct reason';
    };

    subtest "validate_all (all failures)" => sub {
        my $validator2 = GDPR::IAB::TCFv2::Validator->new(
            vendor_id           => 1,
            consent_purpose_ids => [ 1, 7 ],    # Both fail: P1=0, P7=0
        );
        my $result = $validator2->validate_all($tc_string);
        ok !$result, 'validation should fail';
        is scalar( $result->reasons ), 2, 'should have 2 reasons';

        {
            local $\ = " | ";
            like "$result", qr/purpose 1.*\Q | \E.*purpose 7/,
              'should join reasons with ORS';
        }
    };
};

subtest "Validator overrides" => sub {
    my $tc_string = 'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA';

    my $validator = GDPR::IAB::TCFv2::Validator->new(
        vendor_id           => 1,
        consent_purpose_ids => [6],
    );

    ok $validator->validate($tc_string), 'pass for vendor 1';
    ok !$validator->validate( $tc_string, vendor_id => 99 ),
      'fail for vendor 99 (missing bits)';
};

subtest "Validator with Disclosed Vendors" => sub {
    my $tc_v23 =
      'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA.ILrtR_G__bXlv-bb36ftkeYxf9_hr7sQxBgbJs24FzLvW7JwX32E7NEzatqYKmRIAu3TBIQNtHJjURVChKIgVrzDsaEyUoTtKJ-BkiHMRY2NYCFxvm4tjWQCZ5vr_91d9mT-N7dr-2dzyy7hnv3a9_-S1WJidKYetHfv8bBKT-_IU9_x-_4v4_N7pE2-eS1v_tGvt639-4vP_dpvxt-7yffz____73_e7X__d_______Xf_7____________4AAA';

    my $validator = GDPR::IAB::TCFv2::Validator->new(
        vendor_id               => 284,
        check_disclosed_vendors => 1,
    );

    ok $validator->validate($tc_v23), 'pass for disclosed vendor 284';

    my $result = $validator->validate( $tc_v23, vendor_id => 9999 );
    ok !$result, 'fail for non-disclosed vendor 9999';
    like "$result", qr/not disclosed/, 'correct failure reason';
};

subtest "Validator accepts a pre-parsed GDPR::IAB::TCFv2 object" => sub {
    my $tc_string = 'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA';
    my $consent   = GDPR::IAB::TCFv2->Parse($tc_string);

    my $validator = GDPR::IAB::TCFv2::Validator->new(
        vendor_id           => 1,
        consent_purpose_ids => [6],
    );

    my $result = $validator->validate($consent);
    ok $result, 'passes when given a parsed consent object';
    is $result->is_valid, 1, 'is_valid is 1 for the parsed-object input';
};

subtest "Validator without vendor_id" => sub {
    my $tc_string = 'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA';

    my $validator = GDPR::IAB::TCFv2::Validator->new(
        consent_purpose_ids => [6],
    );

    throws_ok { $validator->validate($tc_string) }
    qr/missing vendor_id/,
      'validate croaks when vendor_id is missing in both ctor and override';

    ok $validator->validate( $tc_string, vendor_id => 1 ),
      'override fills the missing vendor_id and validation proceeds';
};

subtest "Validator legitimate_interest_purpose_ids" => sub {
    my $tc_string = 'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA';

    # Vendor 2 has LI for Purpose 2 in this fixture.
    my $validator_pass = GDPR::IAB::TCFv2::Validator->new(
        vendor_id                       => 2,
        legitimate_interest_purpose_ids => [2],
    );
    ok $validator_pass->validate($tc_string),
      'pass for vendor 2 / LI purpose 2';

    # Purpose 1 LI is forbidden by spec regardless of the bit, so this fails.
    my $validator_fail = GDPR::IAB::TCFv2::Validator->new(
        vendor_id                       => 1,
        legitimate_interest_purpose_ids => [1],
    );
    my $result = $validator_fail->validate($tc_string);
    ok !$result,
      'fail for purpose 1 LI (spec forbids LI for Purpose 1 always)';
    like "$result", qr/purpose 1 \(legitimate interest\)/,
      'reason names the LI rule type';
};

subtest "Validator flexible_purpose_ids - scalar form" => sub {
    my $tc_string = 'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA';

    # Plain integer means default_is_li = 0 (consent default).
    # P6/V1 has both consent and LI bits set, so passes either way.
    my $validator = GDPR::IAB::TCFv2::Validator->new(
        vendor_id            => 1,
        flexible_purpose_ids => [6],
    );
    ok $validator->validate($tc_string),
      'flexible P6 (default consent) passes for vendor 1';
};

subtest "Validator flexible_purpose_ids - hashref form" => sub {
    my $tc_string = 'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA';

    # P2/V2 has consent=0 and LI=1, so default_is_li flips the outcome.
    my $validator_consent_default = GDPR::IAB::TCFv2::Validator->new(
        vendor_id            => 2,
        flexible_purpose_ids => [ { purpose_id => 2, default_is_li => 0 } ],
    );
    ok !$validator_consent_default->validate($tc_string),
      'flexible P2/V2 with default_is_li=0 fails (no consent bit)';

    my $validator_li_default = GDPR::IAB::TCFv2::Validator->new(
        vendor_id            => 2,
        flexible_purpose_ids => [ { purpose_id => 2, default_is_li => 1 } ],
    );
    ok $validator_li_default->validate($tc_string),
      'flexible P2/V2 with default_is_li=1 passes (LI bit is set)';
};

subtest "Validator strict mode override" => sub {
    my $tc_string = 'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA';

    # Out-of-range purpose ID 25.
    my $validator = GDPR::IAB::TCFv2::Validator->new(
        vendor_id           => 1,
        consent_purpose_ids => [25],
    );

    # Without strict (the default): the underlying parser warns and returns 0,
    # so the validator reports a normal failure.  Use Test::Warn to swallow
    # the warning while asserting on its content.
    my $result;
    warning_like {
        $result = $validator->validate($tc_string);
    }
    qr/invalid purpose id 25/,
      'underlying parser warns about the invalid id without strict';
    ok !$result, 'invalid purpose id without strict yields a failed result';

    # With strict=1: the underlying parser croaks, and that propagates up
    # through the validator unchanged.
    throws_ok {
        $validator->validate( $tc_string, strict => 1 );
    }
    qr/invalid purpose id 25/,
      'invalid purpose id with strict=1 propagates the parser croak';
};

subtest "Validator validate_all accumulates across rule families" => sub {
    my $tc_string = 'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA';

  # Three failures, one per rule family:
  #   - Consent rule: P1/V1 has consent bit = 0     -> "(consent)"
  #   - LI rule:      P1 LI is spec-forbidden        -> "(legitimate interest)"
  #   - Flexible:     P7/V1 has consent bit = 0     -> "flexible purpose 7"
    my $validator = GDPR::IAB::TCFv2::Validator->new(
        vendor_id                       => 1,
        consent_purpose_ids             => [1],
        legitimate_interest_purpose_ids => [1],
        flexible_purpose_ids => [ { purpose_id => 7, default_is_li => 0 } ],
    );

    my $result = $validator->validate_all($tc_string);
    ok !$result, 'all-fail validation reports failure';
    is scalar( $result->reasons ), 3,
      'one reason per rule family (3 total)';

    my $joined = join '|', $result->reasons;
    like $joined, qr/\(consent\)/,             'has the consent rule reason';
    like $joined, qr/\(legitimate interest\)/, 'has the LI rule reason';
    like $joined, qr/flexible purpose 7/,      'has the flexible rule reason';
};

done_testing;
