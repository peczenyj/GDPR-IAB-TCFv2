use strict;
use warnings;

use Test::More;
use Test::Exception;

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
            like "$result", qr/purpose 1.* | .*purpose 7/,
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

done_testing;
