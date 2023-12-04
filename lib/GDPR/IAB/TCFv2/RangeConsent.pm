package GDPR::IAB::TCFv2::RangeConsent;
use strict;
use warnings;
use integer;
use bytes;

use Carp qw<croak>;

sub new {
    my ( $klass, %args ) = @_;

    my $start = $args{start} or croak "missing field 'start'";
    my $end   = $args{end}   or croak "missing field 'end'";

    croak "ops start should not be bigger than end" if $start > $end;

    my $self = {
        start => $start,
        end   => $end,
    };

    bless $self, $klass;

    return $self;
}

sub contains {
    my ( $self, $id ) = @_;

    return $self->{start} <= $id && $id <= $self->{end};
}

1;
