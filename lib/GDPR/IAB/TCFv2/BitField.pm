package GDPR::IAB::TCFv2::BitField;
use strict;
use warnings;
use integer;
use bytes;

use GDPR::IAB::TCFv2::BitUtils qw<is_set>;
use Carp                       qw<croak>;

sub new {
    my ( $klass, %args ) = @_;

    my $data                 = $args{data}      or croak "missing 'data'";
    my $start_bit            = $args{start_bit} or croak "missing 'start_bit'";
    my $vendor_bits_required = $args{vendor_bits_required}
      or croak "missing 'vendor_bits_required'";

    my $self = {
        data                 => substr( $data, $start_bit ),
        vendor_bits_required => $vendor_bits_required,
    };

    bless $self, $klass;

    return $self;
}

sub max_vendor_id {
    my $self = shift;

    return $self->{vendor_bits_required};
}

sub vendor_consent {
    my ( $self, $id ) = @_;

    croak "invalid vendor id $id: must be positive integer bigger than 0"
      if $id < 1;

    return if $id > $self->{vendor_bits_required};

    return is_set( $self->{data}, $id - 1 );
}

1;
