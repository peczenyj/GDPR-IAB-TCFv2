use strict;
use warnings;

use Test::More;
use Test::Exception;
use FindBin;
use File::Spec;
use lib 'lib';
use GDPR::IAB::TCFv2::CMPValidator;
use GDPR::IAB::TCFv2::Validator;

my $corpus_dir = File::Spec->catdir( $FindBin::Bin, 'corpus' );
my $cmp_file   = File::Spec->catfile( $corpus_dir, 'cmp-list.json' );

# lastUpdated in json is 2026-04-01
# We'll set "now" to 2026-04-15 (14 days old, no warning)
my $now_fresh = 1776254400;

# We'll set "now" to 2026-05-15 (44 days old, should warn)
my $now_stale = 1778846400;

# Helper for testing warnings
sub warning_like (&$;$) {
    my ( $code, $pattern, $message ) = @_;
    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };
    $code->();
    like( join( '', @warnings ), $pattern, $message );
}

subtest "GDPR::IAB::TCFv2::CMPValidator" => sub {
    subtest "loading from file" => sub {
        my $v;

        # Fresh list test
        warning_like {
            $v = GDPR::IAB::TCFv2::CMPValidator->new(
                file => $cmp_file,
                now  => $now_fresh
            );
        }
        qr/^$/, "does not warn if list is fresh";

        isa_ok $v, 'GDPR::IAB::TCFv2::CMPValidator';

        # Stale list test
        warning_like {
            $v = GDPR::IAB::TCFv2::CMPValidator->new(
                file => $cmp_file,
                now  => $now_stale
            );
        }
        qr/CMP list is older than 28 days/, "warns if list is old";

        ok $v->is_valid(21), "CMP 21 is valid (active)";
        ok $v->is_valid(10), "CMP 10 is valid (no deletedDate)";

        # CMP 3 was deleted 2024-11-13.
        ok !$v->is_valid(3), "CMP 3 is invalid (deleted 2024)";

        # CMP 999 is deleted 2026-12-31.
        # At $now_fresh (2026-04-15) it should be VALID.
        ok $v->is_valid(999), "CMP 999 is valid at now_fresh";

        # Create a validator with a date AFTER CMP 999 deletion
        my $v_future = GDPR::IAB::TCFv2::CMPValidator->new(
            file => $cmp_file,
            now  => 1800000000    # 2027+
        );
        ok !$v_future->is_valid(999), "CMP 999 is invalid in future";

        ok !$v->is_valid(9999), "CMP 9999 is invalid (not in list)";
    };

    subtest "loading from raw data" => sub {
        my $json =
          '{"lastUpdated":"2026-05-01T12:00:00Z","cmps":{"1":{"id":1}}}';
        my $v;
        warning_like {
            $v = GDPR::IAB::TCFv2::CMPValidator->new(
                data => $json,
                now  => 1777550400    # 2026-04-30
            );
        }
        qr/^$/, "does not warn if list is fresh";

        ok $v->is_valid(1), "CMP 1 is valid";
    };

    subtest "error handling" => sub {
        throws_ok {
            GDPR::IAB::TCFv2::CMPValidator->new(
                file => "/non/existent/file" );
        }
        qr/Could not open CMP list file/, "throws if file missing";

        throws_ok {
            GDPR::IAB::TCFv2::CMPValidator->new( data => "invalid json" );
        }
        qr/Failed to decode CMP list JSON/, "throws if json invalid";

        throws_ok {
            GDPR::IAB::TCFv2::CMPValidator->new(
                data => '{"wrong":"format"}' );
        }
        qr/Invalid CMP list format/, "throws if format wrong";
    };

    subtest "URL loading (mocked)" => sub {
        eval { require HTTP::Tiny; };
        if ($@) {
            throws_ok {
                GDPR::IAB::TCFv2::CMPValidator->new(
                    url => "http://localhost/cmp.json" );
            }
            qr/HTTP::Tiny is required/, "throws if HTTP::Tiny missing";
        }
        else {
            pass("HTTP::Tiny available, skipping real network test");
        }
    };
};

subtest "Integration with Validator" => sub {
    my $cmp_v = GDPR::IAB::TCFv2::CMPValidator->new(
        file => $cmp_file,
        now  => $now_fresh
    );

    my $tc_traffective =
      'CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA'
      ;    # CMP 21
    my $tc_unknown_cmp =
      'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA';    # CMP 888

    subtest "using CMPValidator object" => sub {
        my $validator = GDPR::IAB::TCFv2::Validator->new(
            vendor_id     => 1,
            cmp_validator => $cmp_v,
        );

        my $res = $validator->validate($tc_traffective);
        ok $res->is_valid, "validation passes with known CMP";

        $res = $validator->validate($tc_unknown_cmp);
        ok !$res->is_valid, "validation fails with unknown CMP";
        is( ( $res->reasons )[0], "CMP 888 is not valid/disclosed",
            "correct reason"
        );
    };

    subtest "using config hashref" => sub {
        my $validator = GDPR::IAB::TCFv2::Validator->new(
            vendor_id     => 1,
            cmp_validator => { file => $cmp_file, now => $now_fresh },
        );

        my $res = $validator->validate($tc_traffective);
        ok $res->is_valid, "validation passes with known CMP (config)";
    };

    subtest "override in validate" => sub {
        my $validator = GDPR::IAB::TCFv2::Validator->new( vendor_id => 1 );

        my $res = $validator->validate(
            $tc_unknown_cmp,
            cmp_validator => { file => $cmp_file, now => $now_fresh }
        );
        ok !$res->is_valid, "validation fails with unknown CMP (override)";
    };
};

done_testing;
