use strict;
use warnings;

use Test::More;
use Test::Exception;

use GDPR::IAB::TCFv2;
use GDPR::IAB::TCFv2::Constants::RestrictionType qw<:all>;

# Helper for testing warnings
sub warning_like (&$;$) {
    my ( $code, $pattern, $message ) = @_;
    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };
    $code->();
    like( join( '', @warnings ), $pattern, $message );
}

subtest "is_vendor_consent_allowed" => sub {
    my $tc_string = 'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA';
    my $consent   = GDPR::IAB::TCFv2->Parse($tc_string);

# Purpose 6: consent allowed, LI allowed. Vendor 1: consent allowed, LI allowed.
# No restriction for P6, V1.
    ok $consent->is_vendor_consent_allowed( 1, 6 ),
      'vendor 1 allowed for purpose 6 (consent)';

# Purpose 7: consent NOT allowed, LI allowed. Vendor 1: consent allowed, LI allowed.
    ok !$consent->is_vendor_consent_allowed( 1, 7 ),
      'vendor 1 NOT allowed for purpose 7 (consent bit is 0)';

# Purpose 1: consent NOT allowed, LI allowed. Vendor 1: consent allowed, LI allowed.
    ok !$consent->is_vendor_consent_allowed( 1, 1 ),
      'vendor 1 NOT allowed for purpose 1 (consent bit is 0)';

 # Restriction check: P7, V32 has restriction RequireConsent (1).
 # Even if bits were set, RequireLegitimateInterest restriction would block it.
 # In this string, P7, V32 does NOT have consent bits anyway.
    ok !$consent->is_vendor_consent_allowed( 32, 7 ),
      'vendor 32 NOT allowed for purpose 7 (consent) due to RequireConsent restriction (and bit 0)';

    # Case: purpose consent is OK, but vendor consent is NOT OK.
    # Purpose 6 is OK. Vendor 99 is NOT in the bitfield.
    ok !$consent->is_vendor_consent_allowed( 99, 6 ),
      'vendor 99 NOT allowed for purpose 6 (vendor bit is 0)';

    # Case: vendor consent is OK, but purpose consent is NOT OK.
    # Vendor 1 is OK. Purpose 7 is NOT OK.
    ok !$consent->is_vendor_consent_allowed( 1, 7 ),
      'vendor 1 NOT allowed for purpose 7 (purpose bit is 0)';
};

subtest "is_vendor_legitimate_interest_allowed" => sub {
    my $tc_string = 'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA';
    my $consent   = GDPR::IAB::TCFv2->Parse($tc_string);

# Purpose 2: consent NOT allowed, LI allowed. Vendor 2: consent allowed, LI allowed.
    ok $consent->is_vendor_legitimate_interest_allowed( 2, 2 ),
      'vendor 2 allowed for purpose 2 (LI)';

    # Restriction check: P7, V32 has restriction RequireConsent (1).
    # This should block LI check even if bits are set.
    ok !$consent->is_vendor_legitimate_interest_allowed( 32, 7 ),
      'vendor 32 NOT allowed for purpose 7 (LI) due to RequireConsent restriction';

    # Case: purpose LI is OK, but vendor LI is NOT OK.
    # All purposes have LI OK in this string. Vendor 99 is NOT in the bitfield.
    ok !$consent->is_vendor_legitimate_interest_allowed( 99, 1 ),
      'vendor 99 NOT allowed for purpose 1 (vendor LI bit is 0)';
};

subtest "is_vendor_allowed_for_flexible_purpose" => sub {
    my $tc_string = 'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA';
    my $consent   = GDPR::IAB::TCFv2->Parse($tc_string);

    # P6, V1: No restrictions. Consent=1, LI=1.
    ok $consent->is_vendor_allowed_for_flexible_purpose( 1, 6, 0 ),
      'flexible P6, V1 (default consent) -> OK';
    ok $consent->is_vendor_allowed_for_flexible_purpose( 1, 6, 1 ),
      'flexible P6, V1 (default LI) -> OK';

    # P2, V2: No restrictions. Consent=0, LI=1.
    ok !$consent->is_vendor_allowed_for_flexible_purpose( 2, 2, 0 ),
      'flexible P2, V2 (default consent) -> NOT OK';
    ok $consent->is_vendor_allowed_for_flexible_purpose( 2, 2, 1 ),
      'flexible P2, V2 (default LI) -> OK';

    # P7, V32: Restriction RequireConsent (1). Consent=0, LI=1.
    # It MUST check consent bit (which is 0).
    ok !$consent->is_vendor_allowed_for_flexible_purpose( 32, 7, 1 ),
      'flexible P7, V32 (default LI) -> NOT OK due to RequireConsent restriction';

    # Test NotAllowed (0) restriction.
    # String COxPe2... has restriction 0 for P2/V32.
    my $tc2 =
      'COxPe2TOxPe2TALABAENAPCgAAAAAAAAAAAAAFAAAAoAAA4IACACAIABgACAFA4ADACAAIygAGADwAQBIAIAIB0AEAEBSACACAA';
    my $consent2 = GDPR::IAB::TCFv2->Parse($tc2);

    ok $consent2->check_publisher_restriction( 2, 0, 32 ),
      'restriction 0 exists for P2/V32';
    ok !$consent2->is_vendor_allowed_for_flexible_purpose( 32, 2, 0 ),
      'flexible P2/V32 (default consent) -> NOT OK due to NotAllowed restriction';
    ok !$consent2->is_vendor_allowed_for_flexible_purpose( 32, 2, 1 ),
      'flexible P2/V32 (default LI) -> NOT OK due to NotAllowed restriction';

    # Also check that NotAllowed blocks fixed methods
    ok !$consent2->is_vendor_consent_allowed( 32, 2 ),
      'vendor 32 NOT allowed for purpose 2 (consent) due to NotAllowed restriction';
    ok !$consent2->is_vendor_legitimate_interest_allowed( 32, 2 ),
      'vendor 32 NOT allowed for purpose 2 (LI) due to NotAllowed restriction';
};
subtest "strictness" => sub {
    my $tc_string = 'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA';

    subtest "default (non-strict)" => sub {
        my $consent = GDPR::IAB::TCFv2->Parse($tc_string);
        my $val;
        warning_like {
            $val = $consent->is_vendor_consent_allowed( 1, 25 );
        }
        qr/invalid purpose id 25/, 'should warn for invalid purpose id';
        is $val, 0, 'should return 0';
    };

    subtest "explicit non-strict" => sub {
        my $consent = GDPR::IAB::TCFv2->Parse($tc_string);
        my $val;
        warning_like {
            $val = $consent->is_vendor_consent_allowed( 1, 0, strict => 0 );
        }
        qr/invalid purpose id 0/, 'should warn for invalid purpose id';
        is $val, 0, 'should return 0';
    };

    subtest "strict mode (constructor)" => sub {
        my $consent = GDPR::IAB::TCFv2->Parse( $tc_string, strict => 1 );
        throws_ok {
            $consent->is_vendor_consent_allowed( 1, 25 );
        }
        qr/invalid purpose id 25/, 'should croak for invalid purpose id';
    };

    subtest "strict mode (override)" => sub {
        my $consent = GDPR::IAB::TCFv2->Parse($tc_string);
        throws_ok {
            $consent->is_vendor_consent_allowed( 1, 25, strict => 1 );
        }
        qr/invalid purpose id 25/, 'should croak for invalid purpose id';
    };
};

done_testing;
