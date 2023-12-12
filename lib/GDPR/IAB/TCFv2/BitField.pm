package GDPR::IAB::TCFv2::BitField;
use strict;
use warnings;
use integer;
use bytes;

use GDPR::IAB::TCFv2::BitUtils qw<is_set>;
use Carp                       qw<croak>;

sub Parse {
    my ( $klass, %args ) = @_;

    croak "missing 'data'"      unless defined $args{data};
    croak "missing 'start_bit'" unless defined $args{start_bit};
    croak "missing 'max_vendor_id'"
      unless defined $args{max_vendor_id};

    my $data          = $args{data};
    my $start_bit     = $args{start_bit};
    my $max_vendor_id = $args{max_vendor_id};

    my $data_size = length($data);

    # add 7 to force rounding to next integer value
    my $bytes_required = ( $max_vendor_id + $start_bit + 7 ) / 8;

    croak
      "a BitField for $max_vendor_id requires a consent string of $bytes_required bytes. This consent string had $data_size"
      if $data_size < $bytes_required;

    my $self = {
        data          => substr( $data, $start_bit ),
        max_vendor_id => $max_vendor_id,
    };

    bless $self, $klass;

    return ( $self, $start_bit + $max_vendor_id );
}

sub max_vendor_id {
    my $self = shift;

    return $self->{max_vendor_id};
}

sub contains {
    my ( $self, $id ) = @_;

    croak "invalid vendor id $id: must be positive integer bigger than 0"
      if $id < 1;

    return if $id > $self->{max_vendor_id};

    return is_set( $self->{data}, $id - 1 );
}

sub all {
    my $self = shift;

    my @data = split //, $self->{data};

    return [ grep { $data[$_] } 1 .. 1 + $self->{max_vendor_id} ];
}

1;
__END__

=head1 NAME

GDPR::IAB::TCFv2::BitField - Transparency & Consent String version 2 bitfield parser

=head1 SYNOPSIS

    my $data = unpack "B*", decode_base64url('tcf v2 consent string base64 encoded');
    
    my $max_vendor_id_consent = << get 16 bits from $data offset 213 >>

    my $bit_field = GDPR::IAB::TCFv2::BitField->Parse(
        data          => $data,
        start_bit     => 230,                   # offset for vendor consents
        max_vendor_id => $max_vendor_id_consent,
    );

    if $bit_field->contains(284) { ... }

=head1 CONSTRUCTOR

Constructor C<Parse> receive 3 parameters: data (as sequence of bits), start bit offset and vendor bits required (max vendor id).

Will die if any parameter is missing.

Will die if data does not contain all bits required.

Will return an array of two elements: the object itself and the next offset.

=head1 METHODS

=head2 contains

Return the vendor id bit status (if enable or not) from the bit field.
Will return false if id is bigger than max vendor id.

    my $ok = $bit_field->contains(284);

=head2 max_vendor_id

Returns the max vendor id.
