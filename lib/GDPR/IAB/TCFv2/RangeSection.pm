package GDPR::IAB::TCFv2::RangeSection;
use strict;
use warnings;
use integer;
use bytes;

use GDPR::IAB::TCFv2::BitUtils qw<is_set get_uint12 get_uint16>;
use GDPR::IAB::TCFv2::RangeConsent;
use Carp            qw<croak>;
use List::MoreUtils qw<any>;

sub new {
    my ( $klass, %args ) = @_;

    my $data                 = $args{data}      or croak "missing 'data'";
    my $start_bit            = $args{start_bit} or croak "missing 'start_bit'";
    my $vendor_bits_required = $args{vendor_bits_required}
      or croak "missing 'vendor_bits_required'";

    # TODO add parse range consent
    my $num_entries = get_uint12( $data, $start_bit );

    my $current_offset = $start_bit + 12;

    my @consents;

    foreach my $i ( 1 .. $num_entries ) {
        my ( $consent, $bits_consumed ) =
          _parse_range_consent( $data, $current_offset,
            $vendor_bits_required );

        push @consents, $consent;

        $current_offset += $bits_consumed;
    }

    my $self = {
        consents             => \@consents,
        vendor_bits_required => $vendor_bits_required,
        _current_offset      => $current_offset,
    };

    bless $self, $klass;

    return $self;
}

sub _parse_range_consent {
    my ( $data, $initial_bit, $max_vendor_id ) = @_;

    my $data_size = length($data);

    croak
      "bit $initial_bit was suppose to start a new range entry, but the consent string was only $data_size bytes long"
      if $data_size <= $initial_bit / 8;

    # If the first bit is set, it's a Range of IDs
    if ( is_set $data, $initial_bit ) {
        my $start = get_uint16( $data, $initial_bit + 1 );
        my $end   = get_uint16( $data, $initial_bit + 17 );

        croak
          "bit $initial_bit range entry exclusion ends at $end, but the max vendor ID is $max_vendor_id"
          if $end > $max_vendor_id;

        return GDPR::IAB::TCFv2::RangeConsent->new( start => $start,
            end => $end ), 33;
    }

    my $vendor_id = get_uint16( $data, $initial_bit + 1 );

    croak
      "bit $initial_bit range entry excludes vendor $vendor_id, but only vendors [1, $max_vendor_id] are valid"
      if $vendor_id > $max_vendor_id;

    return GDPR::IAB::TCFv2::RangeConsent->new( start => $vendor_id,
        end => $vendor_id ), 17;
}

sub current_offset {
    my $self = shift;

    return $self->{_current_offset};
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

    return any { $_->contains($id) } @{ $self->{consents} };
}

1;
