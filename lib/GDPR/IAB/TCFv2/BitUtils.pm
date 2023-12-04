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
  get_uint8
  get_char6
  get_char6_sequence
  get_uint12
  get_uint16
  get_uint36>;

our %EXPORT_TAGS = (
    all => [
        qw<is_set
          get_uint6
          get_uint8
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

sub get_uint8 {
    my ( $data, $offset ) = @_;

    return unpack(
        "C",
        _get_bits_with_padding( $data, 8, $offset, 8 )
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
