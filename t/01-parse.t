use Test::More tests => 2;
use Test::Exception;

use GDPR::IAB::TCFv2;

subtest "valid tcf v2 consent string" => sub {
    plan tests => 21;

    my $consent;

    lives_ok {
        $consent = GDPR::IAB::TCFv2->Parse(
            'CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA.argAC0gAAAAAAAAAAAA'
        );
    }
    'should not throw exception';

    isa_ok $consent, 'GDPR::IAB::TCFv2', 'gdpr iab tcf v2 consent';

    is $consent->version, 2, 'should return version 2';

    is $consent->created, 1228644257,
      'should return the creation epoch 07/12/2008';

    is $consent->last_updated, 1326215413,
      'should return the last update epoch 10/01/2012';

    is $consent->cmp_id, 21, 'should return the cmp id 21';

    is $consent->cmp_version, 7, 'should return the cmp version 7';

    is $consent->consent_screen, 2, 'should return the consent screen 2';

    is $consent->consent_language, "EN",
      'should return the consent language "EN"';

    is $consent->vendor_list_version, 23,
      'should return the vendor list version 23';

    is $consent->policy_version, 2,
      'should return the policy version 2';

    ok $consent->is_service_specific,
      'should return true for service specific';

    ok !$consent->use_non_standard_stacks,
      'should return false for use non standard stacks';

    ok !$consent->purpose_one_treatment,
      'should return false for use purpose one treatment';

    is $consent->publisher_country_code, "KM",
      'should return the publisher country code "KM"';

    is $consent->max_vendor_id, 115, "max vendor id is 115";

    subtest "check purpose consent ids" => sub {
        plan tests => 24;

        my %allowed_purposes = map { $_ => 1 } ( 1, 3, 9, 10 );

        foreach my $id ( 1 .. 24 ) {
            is !!$consent->is_purpose_consent_allowed($id),
              !!$allowed_purposes{$id},
              "checking purpose id $id for consent";
        }
    };

    subtest "check purpose legitimate interest ids" => sub {
        plan tests => 24;

        my %allowed_purposes = map { $_ => 1 } ( 3, 4, 5, 8, 9, 10 );

        foreach my $id ( 1 .. 24 ) {
            is !!$consent->is_purpose_legitimate_interest_allowed($id),
              !!$allowed_purposes{$id},
              "checking purpose id $id for legitimate interest";
        }
    };

    subtest "check special feature opt in" => sub {
        plan tests => 12;

        my %special_feature_opt_in = (
            2 => 1,
        );

        foreach my $id ( 1 .. 12 ) {
            is !!$consent->is_special_feature_opt_in($id),
              !!$special_feature_opt_in{$id},
              "checking special feature id $id opt in";
        }
    };

    subtest "check vendor consent ids" => sub {
        plan tests => 120;

        my %allowed_vendors =
          map { $_ => 1 } (
            2,  3, 6, 7, 8, 10, 12, 13, 14, 15, 16, 21, 25, 27, 30, 31, 34, 35,
            37, 38,   39,  42,  43, 49, 52, 54, 55, 56, 57, 59, 60, 63, 64, 65,
            66, 67,   68,  69,  73, 74, 76, 78, 83, 86, 87, 89, 90, 92, 96, 99,
            100, 106, 109, 110, 114, 115
          );

        foreach my $id ( 1 .. 120 ) {
            is !!$consent->vendor_consent($id),
              !!$allowed_vendors{$id},
              "checking vendor id $id for consent";
        }
    };

    subtest "check vendor legitimate interest ids" => sub {
        plan tests => 120;

        my %allowed_vendors =
          map { $_ => 1 } ( 1, 9, 26, 27, 30, 36, 37, 43, 86, 97, 110, 113 );

        foreach my $id ( 1 .. 120 ) {
            is !!$consent->vendor_legitimate_interest($id),
              !!$allowed_vendors{$id},
              "checking vendor id $id for legitimate interest";
        }
    };
};

subtest "invalid tcf consent string candidates" => sub {
    plan tests => 5;

    throws_ok {
        GDPR::IAB::TCFv2->Parse();
    }
    qr/missing gdpr consent string/,
      'undefined consent string should throw error';

    throws_ok {
        GDPR::IAB::TCFv2->Parse("");
    }
    qr/missing gdpr consent string/, 'empty consent string should throw error';

    throws_ok {
        GDPR::IAB::TCFv2->Parse(
            "BOEFEAyOEFEAyAHABDENAI4AAAB9vABAASAAAAAAAAAA");
    }
    qr/consent string is not tcf version 2/,
      'valid tcf v1 consent string should throw error (deprecated)';

    throws_ok {
        GDPR::IAB::TCFv2->Parse("Clc");
    }
    qr/vendor consent strings are at least 29 bytes long/,
      'short (less than 29 bytes) tcf v2 consent string should throw error';

    throws_ok {
        GDPR::IAB::TCFv2->Parse(
            "DOEFEAyOEFEAyAHABDENAI4AAAB9vABAASAAAAAAAAAA");
    }
    qr/consent string is not tcf version 2/,
      'possible tcf v3 consent string should throw error';
};
