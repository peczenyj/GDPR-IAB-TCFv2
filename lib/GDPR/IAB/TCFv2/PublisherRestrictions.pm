package GDPR::IAB::TCFv2::PublisherRestrictions;
use strict;
use warnings;

use Carp qw<croak>;

sub new {
    my ( $klass, %args ) = @_;

    my $restrictions = $args{restrictions}
      or croak "missing field 'restrictions'";

    my $self = {
        restrictions => $restrictions,
    };

    bless $self, $klass;

    return $self;
}

sub check_publisher_restriction {
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

            foreach my $vendor ( grep { $vendors->{$_} } keys %{$vendors} ) {
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

    my $range = GDPR::IAB::TCFv2::PublisherRestrictions->new(
        restrictions => {
            purpose id => {
                restriction type => instance of GDPR::IAB::TCFv2::RangeSection
            },
        },
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
