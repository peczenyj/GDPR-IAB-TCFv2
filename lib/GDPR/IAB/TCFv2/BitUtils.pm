package GDPR::IAB::TCFv2::BitUtils;
use strict;
use warnings;
use integer;
use bytes;

use feature 'state';

require Exporter;
use base qw<Exporter>;

our @EXPORT_OK = qw<is_set
  get_uint6
  get_char6
  get_char6_sequence
  get_uint12
  get_uint16
  get_uint36>;

our %EXPORT_TAGS = (
    all => [
        qw<is_set
          get_uint6
          get_char6
          get_char6_sequence
          get_uint12
          get_uint16
          get_uint36>
    ]
);

sub is_set {
    my ( $data, $offset ) = @_;

    # TODO check if offset is in range of $data

    return substr( $data, $offset, 1 ) == 1;
}

sub get_uint6 {
    my ( $data, $offset ) = @_;

    return unpack(
        "C",
        _get_bits_with_padding( $data, 8, $offset, 6 )
    );
}

sub get_char6 {
    my ( $data, $offset ) = @_;

    state $char_offset = ord("A");

    return chr( $char_offset + get_uint6( $data, $offset ) );
}

sub get_char6_sequence {
    my ( $data, $offset, $n ) = @_;

    return join "",
      map { get_char6( $data, $offset + ( $_ * 6 ) ) } ( 0 .. $n - 1 );
}

sub get_uint12 {
    my ( $data, $offset ) = @_;

    return unpack(
        "S>",
        _get_bits_with_padding( $data, 16, $offset, 12 )
    );
}

sub get_uint16 {
    my ( $data, $offset ) = @_;

    return unpack(
        "S>",
        _get_bits_with_padding( $data, 16, $offset, 16 )
    );
}

sub get_uint36 {
    my ( $data, $offset ) = @_;

    return unpack(
        "Q>",
        _get_bits_with_padding( $data, 64, $offset, 36 )
    );
}

sub _get_bits_with_padding {
    my ( $data, $bits, $offset, $nbits ) = @_;

    # TODO check if offset is in range of $data ?

    my $padding = "0" x ( $bits - $nbits );

    return pack( "B${bits}", $padding . substr( $data, $offset, $nbits ) );
}

1;
__END__

=head1 NAME 

GDPR::IAB::TCFv2::BitUtils - utilities functions to manage bits
 
=head1 SYNOPSIS
    use GDPR::IAB::TCFv2::BitUtils qw<get_uint16>;

    my $data = unpack "B*", decode_base64url('tcf v2 consent string base64 encoded');
    
    my $max_vendor_id_consent = get_uint16($data, 213);

=head1 FUNCTIONS

=head2 is_set

Receive two parameters: data and bit offset.

Will return true if the bit present on bit offset is 1.

    my $is_service_specific = is_set( $data, 138 );

=head2 get_uint6

Receive two parameters: data and bit offset.

Will fetch 6 bits from data since bit offset and convert it an unsigned int.

    my $version = get_uint6( $data, 0 );

=head2 get_char6

Similar to L<GDPR::IAB::TCFv2::BitUtils::get_uint6> but perform increment the value with the ascii value of "A" letter and convert to a character.

=head2 get_char6_sequence

Receives the data, bit offset and sequence size n.

Returns a string of size n by concantenating L<GDPR::IAB::TCFv2::BitUtils::get_char6> calls.

    my $consent_language = get_char6_sequence($data, 108, 2) # returns two letter country encoded as ISO_639-1 

=head2 get_uint12

Receives the data and bit offset.

Will fetch 12 bits from data since bit offset and convert it an unsigned int (short).

    my $cmp_id = get_uint12( $data, 78 );

=head2 get_uint16

Receives the data and bit offset.

Will fetch 16 bits from data since bit offset and convert it an unsigned int (short).

    my $max_vendor_id_consent = get_uint16( $data, 213 );

=head2 get_uint36

Receives the data and bit offset.

Will fetch 36 bits from data since bit offset and convert it an unsigned int (long).

    my $deciseconds = get_uint36( $data, 6 );
    my $created = $deciseconds/2;

