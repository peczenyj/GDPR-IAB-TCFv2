package GDPR::IAB::TCFv2::Publisher;
use strict;
use warnings;

use Carp qw<croak>;

use GDPR::IAB::TCFv2::PublisherRestrictions;
use GDPR::IAB::TCFv2::PublisherTC;


sub Parse {
    my ( $klass, %args ) = @_;

    croak "missing 'core_data'"      unless defined $args{core_data};
    croak "missing 'core_data_size'" unless defined $args{core_data_size};

    croak "missing 'options'"      unless defined $args{options};
    croak "missing 'options.json'" unless defined $args{options}->{json};

    my $core_data      = $args{core_data};
    my $core_data_size = $args{core_data_size};

    my $restrictions = GDPR::IAB::TCFv2::PublisherRestrictions->Parse(
        data      => $core_data,
        data_size => $core_data_size,
        options   => $args{options},
    );

    my $self = {
        restrictions => $restrictions,
        publisher_tc => undef,
    };

    if ( defined $args{publisher_tc_data} ) {
        my $publisher_tc_data = $args{publisher_tc_data};
        my $publisher_tc_data_size =
          $args{publisher_tc_data_size} || length($publisher_tc_data);

        my $publisher_tc = GDPR::IAB::TCFv2::PublisherTC->Parse(
            data      => $publisher_tc_data,
            data_size => $publisher_tc_data_size,
            options   => $args{options},
        );

        $self->{publisher_tc} = $publisher_tc;
    }

    bless $self, $klass;

    return $self;
}

sub check_restriction {
    my ( $self, $purpose_id, $restrict_type, $vendor ) = @_;

    return $self->{restrictions}
      ->contains( $purpose_id, $restrict_type, $vendor );
}

sub publisher_tc {
    my ( $self, $callback ) = @_;

    return $self->{publisher_tc};
}

sub TO_JSON {
    my $self = shift;

    my %tags = (
        restrictions => $self->{restrictions}->TO_JSON,
    );

    if ( defined $self->{publisher_tc} ) {
        %tags = ( %tags, %{ $self->{publisher_tc}->TO_JSON } );
    }

    return \%tags;
}

1;
