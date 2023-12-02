package GDPR::IAB::TCFv2;
use strict;
use warnings;
use integer;
use bytes;

use MIME::Base64 qw<decode_base64>;
use Carp         qw<croak>;


my $CONSENT_STRING_TCF2_SEPARATOR = '.';
my $CONSENT_STRING_TCF2_PREFIX    = 'C';
my $DECIS_PER_ONE                 = 10;
my $MIN_BIT_SIZE                  = 29 * 8;


sub Parse {
    my ( $klass, $gdpr_consent_string ) = @_;

    croak 'missing gdpr consent string' unless $gdpr_consent_string;

    croak 'consent string is not tcf version 2'
      unless isConsentV2($gdpr_consent_string);

    $gdpr_consent_string = substr(
        $gdpr_consent_string, 0,
        index( $gdpr_consent_string, $CONSENT_STRING_TCF2_SEPARATOR )
    );

    my $data = unpack 'B*', decode_base64($gdpr_consent_string);

    croak 'vendor consent strings are at least 29 bytes long'
      if length($data) < $MIN_BIT_SIZE;

    my $self = {
        data => $data,
    };

    bless $self, $klass;

    croak 'consent string is not tcf version 2' unless $self->version == 2;

    croak 'invalid vendor list version' if $self->vendor_list_version == 0;

    return $self;
}

sub version {
    my $self = shift;

    return unpack(
        "C",
        pack( "B8", ( "0" x ( 8 - 6 ) ) . substr( $self->{data}, 0, 6 ) )
    );
}

sub created {
    my $self = shift;

    my $deciseconds = unpack(
        "Q>",
        pack( "B64", ( "0" x ( 64 - 36 ) ) . substr( $self->{data}, 6, 36 ) )
    );

    return $deciseconds / $DECIS_PER_ONE;
}

sub last_updated {
    my $self = shift;

    my $deciseconds = unpack(
        "Q>",
        pack( "B64", ( "0" x ( 64 - 36 ) ) . substr( $self->{data}, 42, 36 ) )
    );

    return $deciseconds / $DECIS_PER_ONE;
}

sub cmp_id {
    my $self = shift;

    return unpack(
        "S>",
        pack( "B16", ( "0" x ( 16 - 12 ) ) . substr( $self->{data}, 78, 12 ) )
    );
}

sub cmp_version {
    my $self = shift;

    return unpack(
        "S>",
        pack( "B16", ( "0" x ( 16 - 12 ) ) . substr( $self->{data}, 90, 12 ) )
    );
}

sub consent_screen {
    my $self = shift;

    return unpack(
        "C",
        pack( "B8", ( "0" x ( 8 - 6 ) ) . substr( $self->{data}, 102, 6 ) )
    );
}

sub consent_language {
    my $self = shift;

    my @letters = unpack "C*", pack(
        "B8B8",
        ( "0" x ( 8 - 6 ) ) . substr( $self->{data}, 108, 6 ),
        ( "0" x ( 8 - 6 ) ) . substr( $self->{data}, 114, 6 )
    );

    return chr( $letters[0] + 65 ) . chr( $letters[1] + 65 );
}

sub vendor_list_version {
    my $self = shift;

    return unpack(
        "S>",
        pack(
            "B16", ( "0" x ( 16 - 12 ) ) . substr( $self->{data}, 120, 12 )
        )
    );
}

sub is_purpose_allowed {
    my $self = shift;
    my $id   = shift;

    return if $id > 24;

    return substr( $self->{data}, 151 + $id, 1 );
}

sub isConsentV2 {
    my ($gdpr_consent_string) = @_;

    return rindex( $gdpr_consent_string, $CONSENT_STRING_TCF2_PREFIX, 0 ) == 0;
}

1;
