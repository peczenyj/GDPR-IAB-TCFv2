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

# Fixture lastUpdated is 2026-04-01.  Pin "now" deterministically:
#   2026-04-15 -> 14 days fresh, no warning
#   2026-05-15 -> 44 days stale, warns
my $now_fresh = 1776254400;
my $now_stale = 1778846400;

sub warning_like (&$;$) {
    my ( $code, $pattern, $message ) = @_;
    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };
    $code->();
    like( join( '', @warnings ), $pattern, $message );
}

subtest "CMPValidator: loading from file" => sub {
    my $v;

    warning_like {
        $v = GDPR::IAB::TCFv2::CMPValidator->new(
            file => $cmp_file,
            now  => $now_fresh,
        );
    }
    qr/^$/, "no warning for fresh list";

    isa_ok $v, 'GDPR::IAB::TCFv2::CMPValidator';

    warning_like {
        $v = GDPR::IAB::TCFv2::CMPValidator->new(
            file => $cmp_file,
            now  => $now_stale,
        );
    }
    qr/CMP list is older than 28 days/, "warns when list is stale";

    ok $v->is_valid(21),    "CMP 21 is active";
    ok $v->is_valid(10),    "CMP 10 has no deletedDate";
    ok !$v->is_valid(3),    "CMP 3 is deleted (2024-11-13)";
    ok $v->is_valid(999),   "CMP 999 is still valid at fresh-now";
    ok !$v->is_valid(9999), "CMP 9999 is unknown";

    my $v_future;
    {
        # Constructing with now = 2027 would emit the >28-days warning;
        # that's expected here, just don't let it leak into the test
        # output.
        local $SIG{__WARN__} = sub { };
        $v_future = GDPR::IAB::TCFv2::CMPValidator->new(
            file => $cmp_file,
            now  => 1800000000,    # 2027+
        );
    }
    ok !$v_future->is_valid(999), "CMP 999 invalid past its deletedDate";
};

subtest "CMPValidator: loading from raw data" => sub {
    my $json = '{"lastUpdated":"2026-05-01T12:00:00Z","cmps":{"1":{"id":1}}}';
    my $v;

    warning_like {
        $v = GDPR::IAB::TCFv2::CMPValidator->new(
            data => $json,
            now  => 1777550400,    # 2026-04-30
        );
    }
    qr/^$/, "no warning for fresh raw data";

    ok $v->is_valid(1), "CMP 1 known";
};

subtest "CMPValidator: error handling" => sub {
    throws_ok {
        GDPR::IAB::TCFv2::CMPValidator->new( file => "/non/existent" );
    }
    qr/Could not open CMP list file/, "missing file croaks";

    throws_ok {
        GDPR::IAB::TCFv2::CMPValidator->new( data => "not-json" );
    }
    qr/Failed to decode CMP list JSON/, "bad JSON croaks";

    throws_ok {
        GDPR::IAB::TCFv2::CMPValidator->new( data => '{"wrong":"shape"}' );
    }
    qr/Invalid CMP list format/, "missing 'cmps' key croaks";
};

subtest "CMPValidator: URL fetch is opt-in" => sub {

    # Without network_ok the constructor must refuse, regardless of
    # whether HTTP::Tiny is installed -- the gate is on intent, not
    # on the dependency.
    throws_ok {
        GDPR::IAB::TCFv2::CMPValidator->new(
            url => 'http://localhost/cmp.json' );
    }
    qr/refusing to fetch.*network_ok was not set/,
      "url without network_ok croaks";

    # With network_ok the constructor proceeds; if HTTP::Tiny is
    # missing, that croak should fire.  If it is installed, the call
    # would actually try to dial out -- skip in that case to avoid a
    # flaky test.
    if ( eval { require HTTP::Tiny; 1 } ) {
        pass
          "HTTP::Tiny available -- skipping live network call (would dial out)";
    }
    else {
        throws_ok {
            GDPR::IAB::TCFv2::CMPValidator->new(
                url        => 'http://localhost/cmp.json',
                network_ok => 1,
            );
        }
        qr/HTTP::Tiny is required/,
          "url with network_ok croaks when HTTP::Tiny missing";
    }
};

subtest "Validator integration: cmp_validator object" => sub {
    my $cmp_v = GDPR::IAB::TCFv2::CMPValidator->new(
        file => $cmp_file,
        now  => $now_fresh,
    );

    # CMP 21 -- known and active in the fixture
    my $tc_known =
      'CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA';

    # CMP 888 -- not in the fixture
    my $tc_unknown = 'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA';

    my $validator = GDPR::IAB::TCFv2::Validator->new(
        vendor_id     => 1,
        cmp_validator => $cmp_v,
    );

    ok $validator->validate($tc_known)->is_valid,
      "validation passes when CMP is known";

    my $bad = $validator->validate($tc_unknown);
    ok !$bad->is_valid, "validation fails when CMP is unknown";
    is( ( $bad->reasons )[0],
        "CMP 888 is not valid/disclosed", "reason names the bad CMP"
    );
};

subtest "Validator integration: cmp_validator hashref auto-instantiates" =>
  sub {
    my $tc_known =
      'CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA';

    my $validator = GDPR::IAB::TCFv2::Validator->new(
        vendor_id     => 1,
        cmp_validator => { file => $cmp_file, now => $now_fresh },
    );

    ok $validator->validate($tc_known)->is_valid,
      "hashref form works as well as object form";
  };

subtest "Validator integration: per-call override" => sub {
    my $tc_unknown = 'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA';

    # Validator constructed without a cmp_validator -- the rule is off
    my $validator = GDPR::IAB::TCFv2::Validator->new( vendor_id => 1 );
    ok $validator->validate($tc_unknown)->is_valid,
      "no cmp rule -> CMP 888 passes";

    # Per-call override turns the rule on.  Hashref form gets coerced.
    my $bad = $validator->validate(
        $tc_unknown,
        cmp_validator => { file => $cmp_file, now => $now_fresh },
    );
    ok !$bad->is_valid, "per-call cmp_validator override fails the bad CMP";
};

subtest "Validator integration: bad cmp_validator value croaks" => sub {
    throws_ok {
        GDPR::IAB::TCFv2::Validator->new(
            vendor_id     => 1,
            cmp_validator => 42,
        );
    }
    qr/cmp_validator must be a GDPR::IAB::TCFv2::CMPValidator/,
      "non-object, non-hashref cmp_validator croaks";
};

done_testing;
