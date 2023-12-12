package GDPR::IAB::TCFv2::RangeSection;
use strict;
use warnings;
use integer;
use bytes;

use GDPR::IAB::TCFv2::BitUtils qw<is_set get_uint12 get_uint16>;
use GDPR::IAB::TCFv2::RangeConsent;
use Carp qw<croak>;

sub Parse {
    my ( $klass, %args ) = @_;

    croak "missing 'data'"      unless defined $args{data};
    croak "missing 'start_bit'" unless defined $args{start_bit};
    croak "missing 'max_vendor_id'"
      unless defined $args{max_vendor_id};

    croak "missing 'options'"      unless defined $args{options};
    croak "missing 'options.json'" unless defined $args{options}->{json};

    my $data          = $args{data};
    my $start_bit     = $args{start_bit};
    my $max_vendor_id = $args{max_vendor_id};
    my $options       = $args{options};

    my $data_size = length($data);

    croak
      "a BitField for vendor consent strings using RangeSections require at least 31 bytes. Got $data_size"
      if $data_size < 32;

    my ( $num_entries, $next_offset ) = get_uint12( $data, $start_bit );

    my @range_consents;

    foreach my $i ( 1 .. $num_entries ) {
        my $range_consent;
        ( $range_consent, $next_offset ) = _parse_range_consent(
            $data, $next_offset,
            $max_vendor_id,
            $options,
        );

        push @range_consents, $range_consent;
    }

    my $self = {
        range_consents => \@range_consents,
        max_vendor_id  => $max_vendor_id,
        options        => $options,
    };

    bless $self, $klass;

    return ( $self, $next_offset );
}

sub _parse_range_consent {
    my ( $data, $initial_bit, $max_vendor_id, $options ) = @_;

    my $data_size = length($data);

    croak
      "bit $initial_bit was suppose to start a new range entry, but the consent string was only $data_size bytes long"
      if $data_size <= $initial_bit / 8;

    # If the first bit is set, it's a Range of IDs
    my ( $is_range, $next_offset ) = is_set $data, $initial_bit;
    if ($is_range) {
        my ( $start, $end );

        ( $start, $next_offset ) = get_uint16( $data, $next_offset );
        ( $end,   $next_offset ) = get_uint16( $data, $next_offset );

        croak
          "bit $initial_bit range entry exclusion ends at $end, but the max vendor ID is $max_vendor_id"
          if $end > $max_vendor_id;

        return GDPR::IAB::TCFv2::RangeConsent->new(
            start   => $start,
            end     => $end,
            options => $options,
          ),
          $next_offset;
    }

    my $vendor_id;

    ( $vendor_id, $next_offset ) = get_uint16( $data, $next_offset );

    croak
      "bit $initial_bit range entry excludes vendor $vendor_id, but only vendors [1, $max_vendor_id] are valid"
      if $vendor_id > $max_vendor_id;

    return GDPR::IAB::TCFv2::RangeConsent->new(
        start   => $vendor_id,
        end     => $vendor_id,
        options => $options,
      ),
      $next_offset;
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

    foreach my $range_consent ( @{ $self->{range_consents} } ) {
        return 1 if $range_consent->contains($id);
    }

    return 0;
}

sub all {
    my $self = shift;

    my @vendors;
    foreach my $range_consent ( @{ $self->{range_consents} } ) {
        push @vendors, @{ $range_consent->all };
    }

    return \@vendors;
}

sub TO_JSON {
    my $self = shift;

    if ( !!$self->{options}->{json}->{compact} ) {
        my @vendors;

        foreach my $range_consent ( @{ $self->{range_consents} } ) {
            push @vendors, @{ $range_consent->TO_JSON }
              ;    # todo use all when we convert back to arrayref
        }

        return \@vendors;
    }

    my ( $false, $true ) = @{ $self->{options}->{json}->{boolean_values} };

    my %map;
    if ( !!$self->{options}->{json}->{verbose} ) {
        %map = map { $_ => $false } 1 .. $self->{max_vendor_id};
    }

    foreach my $range_consent ( @{ $self->{range_consents} } ) {
        %map = ( %map, %{ $range_consent->TO_JSON } );
    }

    return \%map;
}

1;
__END__

=head1 NAME

GDPR::IAB::TCFv2::RangeSection - Transparency & Consent String version 2 range section parser

=head1 SYNOPSIS

    my $data = unpack "B*", decode_base64url('tcf v2 consent string base64 encoded');
    
    my $max_vendor_id_consent = << get 16 bits from $data offset 213 >>

    my ($range_section, $next_offset) = GDPR::IAB::TCFv2::RangeSection->Parse(
        data          => $data,
        start_bit     => 230,                      # offset for vendor range_consents
        max_vendor_id => $max_vendor_id_consent,
    );

    if $range_section->contains(284) { ... }

=head1 CONSTRUCTOR

Constructor C<Parse> receives 3 parameters: data (as sequence of bits), start bit offset and vendor bits required (max vendor id).

Will die if any parameter is missing.

Will die if data does not contain all bits required.

Will die if the range sections are malformed.

Will return an array of two elements: the object itself and the next offset.

=head1 METHODS

=head2 contains

Return the vendor id bit status (if enable or not) from one of the range sections.

Will return false if id is bigger than max vendor id.

    my $ok = $range_section->contains(284);

=head2 max_vendor_id

Returns the max vendor id.

=head2 all

Returns an arrayref of all vendors mapped with the bit enabled.

It is a combination of all the responses of L<GDPR::IAB::TCFv2::RangeConsent#all>.
