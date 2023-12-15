package GDPR::IAB::TCFv2::PublisherRestrictions;
use strict;
use warnings;

use Carp qw<croak>;

use GDPR::IAB::TCFv2::BitUtils qw<is_set
  get_uint2
  get_uint3
  get_uint6
  get_uint12
  get_uint16
  get_uint36
  get_char6_pair
>;

use constant ASSUMED_MAX_VENDOR_ID => 0x7FFF;    # 32767 or (1 << 15) -1


sub Parse {
    my ( $klass, %args ) = @_;

    croak "missing 'data'"      unless defined $args{data};
    croak "missing 'data_size'" unless defined $args{data_size};

    croak "missing 'options'"      unless defined $args{options};
    croak "missing 'options.json'" unless defined $args{options}->{json};

    my $data      = $args{data};
    my $data_size = $args{data_size};
    my $offset    = 0;
    my $max_id    = ASSUMED_MAX_VENDOR_ID;
    my $options   = $args{options};

    my ( $num_restrictions, $next_offset ) = get_uint12( $data, $offset );

    my %restrictions;

    for ( 1 .. $num_restrictions ) {
        my ( $purpose_id, $restriction_type, $vendor_restrictions );

        ( $purpose_id, $next_offset ) = get_uint6( $data, $next_offset );

        ( $restriction_type, $next_offset ) = get_uint2( $data, $next_offset );

        ( $vendor_restrictions, $next_offset ) =
          GDPR::IAB::TCFv2::RangeSection->Parse(
            data      => $data,
            data_size => $data_size,
            offset    => $next_offset,
            max_id    => ASSUMED_MAX_VENDOR_ID,
            options   => $options,
          );

        $restrictions{$purpose_id} ||= {};

        $restrictions{$purpose_id}->{$restriction_type} = $vendor_restrictions;
    }

    my $self = {
        restrictions => \%restrictions,
    };

    bless $self, $klass;

    return $self;
}

sub max_id {
    my $self = @_;

    return ASSUMED_MAX_VENDOR_ID;
}

sub contains {
    my ( $self, $purpose_id, $restrict_type, $vendor ) = @_;

    return 0
      unless exists $self->{restrictions}->{$purpose_id}->{$restrict_type};

    return $self->{restrictions}->{$purpose_id}->{$restrict_type}
      ->contains($vendor);
}

sub TO_JSON {
    my $self = shift;

    my %publisher_restrictions;

    foreach my $purpose_id ( keys %{ $self->{restrictions} } ) {
        my $restriction_map = $self->{restrictions}->{$purpose_id};

        my %purpose_restrictions;

        foreach my $restrict_type ( keys %{$restriction_map} ) {
            my $vendors = $restriction_map->{$restrict_type}->all;

            foreach my $vendor ( @{$vendors} ) {
                $purpose_restrictions{$vendor} = int($restrict_type);
            }
        }

        $publisher_restrictions{$purpose_id} = \%purpose_restrictions;
    }

    return \%publisher_restrictions;
}

1;
__END__

=head1 NAME

GDPR::IAB::TCFv2::PublisherRestrictions - Transparency & Consent String version 2 publisher restriction

=head1 SYNOPSIS

    my ($publisher_restrictions, $next_offset) = GDPR::IAB::TCFv2::PublisherRestrictions->Parse(
        data => $self->{data},
        offset => $pub_restrict_offset,
        max_id =>ASSUMED_MAX_VENDOR_ID,
        options => $self->{options},
    );

    die "there is publisher restriction on purpose id 1, type 0 on vendor 284"
        if $range->contains(1, 0, 284);

=head1 CONSTRUCTOR

Receive 1 parameters: restrictions. Hashref.

Will die if it is undefined.

=head1 METHODS

=head2 contains

Return true for a given combination of purpose id, restriction type and vendor 

    my $purpose_id = 1;
    my $restriction_type = 0;
    my $vendor = 284;
    $ok = $range->contains($purpose_id, $restriction_type, $vendor);

=head2 max_id

Returns the max vendor id.

=head2 TO_JSON

Returns a hashref with the following format:

    {
        '[purpose id]' => {
            # 0 - Not Allowed
            # 1 - Require Consent
            # 2 - Require Legitimate Interest
            '[vendor id]' => 1,
        },
    }

Example, by parsing the consent C<COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA> we can generate this hashref.

    {
        "7" => {
            "32" => 1
        }
    }
