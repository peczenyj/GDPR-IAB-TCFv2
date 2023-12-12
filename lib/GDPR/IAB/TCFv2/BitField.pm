package GDPR::IAB::TCFv2::BitField;
use strict;
use warnings;
use integer;
use bytes;

use GDPR::IAB::TCFv2::BitUtils qw<is_set>;
use Carp                       qw<croak>;

sub Parse {
    my ( $klass, %args ) = @_;

    croak "missing 'data'"   unless defined $args{data};
    croak "missing 'offset'" unless defined $args{offset};
    croak "missing 'max_id'"
      unless defined $args{max_id};

    croak "missing 'options'"      unless defined $args{options};
    croak "missing 'options.json'" unless defined $args{options}->{json};

    my $data    = $args{data};
    my $offset  = $args{offset};
    my $max_id  = $args{max_id};
    my $options = $args{options};

    my $data_size = length($data);

    # add 7 to force rounding to next integer value
    my $bytes_required = ( $max_id + $offset + 7 ) / 8;

    croak
      "a BitField for $max_id requires a consent string of $bytes_required bytes. This consent string had $data_size"
      if $data_size < $bytes_required;

    my $self = {

        # TODO consider store data as arrayref of bits
        data    => substr( $data, $offset, $max_id ),
        max_id  => $max_id,
        options => $options,
    };

    bless $self, $klass;

    return ( $self, $offset + $max_id );
}

sub contains {
    my ( $self, $id ) = @_;

    croak "invalid vendor id $id: must be positive integer bigger than 0"
      if $id < 1;

    return if $id > $self->{max_id};

    return is_set( $self->{data}, $id - 1 );
}

sub TO_JSON {
    my $self = shift;

    my @data = split //, $self->{data};

    if ( !!$self->{options}->{json}->{compact} ) {
        return [ grep { $data[ $_ - 1 ] } 1 .. $self->{max_id} ];
    }

    my ( $false, $true ) = @{ $self->{options}->{json}->{boolean_values} };

    if ( !!$self->{options}->{json}->{verbose} ) {
        return { map { $_ => $data[ $_ - 1 ] ? $true : $false }
              1 .. $self->{max_id} };
    }

    return {
        map  { $_ => $true }
        grep { $data[ $_ - 1 ] } 1 .. $self->{max_id}
    };
}

sub _format_json_subsection2 {
    my ( $self, $data, $max ) = @_;

    my ( $false, $true ) = @{ $self->{options}->{json}->{boolean_values} };

    if ( !!$self->{options}->{json}->{compact} ) {
        return [
            grep { $data->{$_} } 1 .. $max,
        ];
    }

    my $verbose = !!$self->{options}->{json}->{verbose};

    return $data if $verbose;

    return { map { $_ => $true } grep { $data->{$_} } keys %{$data} };
}

1;
__END__

=head1 NAME

GDPR::IAB::TCFv2::BitField - Transparency & Consent String version 2 bitfield parser

=head1 SYNOPSIS

    my $data = unpack "B*", decode_base64url('tcf v2 consent string base64 encoded');
    
    my $max_id_consent = << get 16 bits from $data offset 213 >>

    my $bit_field = GDPR::IAB::TCFv2::BitField->Parse(
        data          => $data,
        offset     => 230,                   # offset for vendor consents
        max_id => $max_id_consent,
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

=head2 max_id

Returns the max vendor id.

=head2 all

Returns an array of all vendors mapped with the bit enabled.
