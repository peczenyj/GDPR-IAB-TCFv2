package GDPR::IAB::TCFv2::Validator::Result;

use strict;
use warnings;

use overload
  bool => sub { $_[0]->{ok} },
  '""' => sub {
    my $self = shift;
    return '' if $self->{ok};

    # Use $ORS (Output Record Separator) or newline as fallback
    my $sep = defined($\) ? $\ : "\n";
    return join( $sep, @{ $self->{reasons} || [] } );
  };

sub new {
    my ( $klass, %args ) = @_;

    my $self = {
        ok      => $args{ok}      || 0,
        reasons => $args{reasons} || [],
    };

    return bless $self, $klass;
}

sub is_valid { $_[0]->{ok} }

sub reasons {
    my $self = shift;
    return @{ $self->{reasons} || [] };
}

1;
