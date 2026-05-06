use strict;
use warnings;

use Test::More;
use Test::Exception;

use GDPR::IAB::TCFv2;
use GDPR::IAB::TCFv2::BitUtils;

# These flags decide whether the BitUtils helpers take the fast
# pack 'S>' / 'Q>' path or the Math::BigInt fallback.  On modern
# Perls both flags are true; on Perl < 5.10 (e.g. 5.8.9 on FreeBSD,
# CPAN Testers report 281cd334-...) the fallback is the only path.
#
# Forcing both flags off here exercises the fallback unconditionally
# so the regression is testable on any Perl.
#
# Regression: the fallback used to return raw Math::BigInt blessed
# objects, which then propagated into TO_JSON output and made any
# JSON encoder without `convert_blessed` croak with
# "encountered object 'Math::BigInt=HASH(...)'...".

my $tc_string =
  'CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA';

subtest 'fallback path returns plain scalars (no blessed Math::BigInt)' =>
  sub {
    local $GDPR::IAB::TCFv2::BitUtils::CAN_PACK_QUADS       = 0;
    local $GDPR::IAB::TCFv2::BitUtils::CAN_FORCE_BIG_ENDIAN = 0;

    my $consent;
    lives_ok { $consent = GDPR::IAB::TCFv2->Parse($tc_string) }
    'Parse succeeds with both fast paths disabled';

    for my $accessor (
        qw< cmp_id cmp_version vendor_list_version policy_version
        max_vendor_id_consent max_vendor_id_legitimate_interest
        created last_updated >
      )
    {
        my $value = $consent->$accessor;
        is ref($value), '',
          "$accessor returns a plain scalar (got "
          . ( ref($value) || 'scalar' ) . ')';
    }
  };

subtest 'fallback values JSON-encode without convert_blessed' => sub {
    local $GDPR::IAB::TCFv2::BitUtils::CAN_PACK_QUADS       = 0;
    local $GDPR::IAB::TCFv2::BitUtils::CAN_FORCE_BIG_ENDIAN = 0;

    my $json_class =
        eval { require JSON;     1 } ? 'JSON'
      : eval { require JSON::PP; 1 } ? 'JSON::PP'
      :                                undef;
    plan skip_all => 'no JSON encoder available' unless $json_class;

    my $consent = GDPR::IAB::TCFv2->Parse($tc_string);

    # Deliberately do NOT enable convert_blessed.  A blessed Math::BigInt
    # leaking through TO_JSON would croak here.
    my $encoder = $json_class->new;
    my $output;
    lives_ok { $output = $encoder->encode( $consent->TO_JSON ) }
    'TO_JSON encodes cleanly without convert_blessed';

    like $output, qr/"cmp_id"\s*:\s*\d+/,
      'cmp_id is encoded as a JSON number';
    like $output, qr/"vendor_list_version"\s*:\s*\d+/,
      'vendor_list_version is encoded as a JSON number';
};

done_testing;
