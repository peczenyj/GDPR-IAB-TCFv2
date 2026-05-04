package GDPR::IAB::TCFv2::CMPValidator;

use strict;
use warnings;

use Carp     qw<croak carp>;
use JSON::PP ();
use Time::Piece;

sub new {
    my ( $klass, %args ) = @_;

    my $self = {
        cmps         => {},
        last_updated => undef,
        now          => $args{now},
    };
    bless $self, $klass;

    if ( $args{file} ) {
        $self->load_from_file( $args{file} );
    }
    elsif ( $args{url} ) {
        $self->load_from_url( $args{url} );
    }
    elsif ( $args{data} ) {
        $self->load_from_data( $args{data} );
    }

    return $self;
}

sub load_from_file {
    my ( $self, $path ) = @_;

    open my $fh, '<', $path
      or croak "Could not open CMP list file '$path': $!";
    my $content = do { local $/ = undef; <$fh> };
    close $fh;

    return $self->load_from_data($content);
}

sub load_from_url {
    my ( $self, $url ) = @_;

    eval {
        require HTTP::Tiny;
        1;
    }
      or croak "HTTP::Tiny is required to load CMP list from URL. "
      . "Please install it or use a local file instead.";

    my $response = HTTP::Tiny->new->get($url);
    croak "Failed to fetch CMP list from '$url': $response->{reason}"
      unless $response->{success};

    return $self->load_from_data( $response->{content} );
}

sub load_from_data {
    my ( $self, $json_text ) = @_;

    my $data = eval { JSON::PP->new->utf8->decode($json_text) };
    croak "Failed to decode CMP list JSON: $@" if $@;

    croak "Invalid CMP list format: missing 'cmps' key"
      unless ref $data eq 'HASH' && $data->{cmps};

    $self->{cmps}         = $data->{cmps};
    $self->{last_updated} = $data->{lastUpdated};

    $self->_check_age();

    return $self;
}

sub is_valid {
    my ( $self, $cmp_id ) = @_;

    my $cmp = $self->{cmps}->{$cmp_id};
    return 0 unless $cmp;

    if ( $cmp->{deletedDate} ) {
        my $deleted = $self->_parse_date( $cmp->{deletedDate} );
        return 0 if $deleted && $deleted <= $self->_now();
    }

    return 1;
}

sub last_updated_epoch {
    my ($self) = @_;
    return unless $self->{last_updated};
    return $self->_parse_date( $self->{last_updated} );
}

sub _check_age {
    my ($self) = @_;

    my $epoch = $self->last_updated_epoch();
    return unless $epoch;

    my $age_days = ( $self->_now() - $epoch ) / 86400;
    if ( $age_days > 28 ) {
        carp sprintf "CMP list is older than 28 days (last updated: %s)",
          $self->{last_updated};
    }
}

sub _now {
    my ($self) = @_;
    return $self->{now} || time();
}

sub _parse_date {
    my ( $self, $date_str ) = @_;

# IAB Registry format is typically "2020-04-27T20:27:54.2Z" or "2020-04-27T20:27:54Z"
# We'll use a simple regex to extract parts for Time::Piece to be robust
    if ( $date_str =~ /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/ ) {
        my $t_str = "$1-$2-$3 $4:$5:$6";
        my $epoch =
          eval { Time::Piece->strptime( $t_str, "%Y-%m-%d %H:%M:%S" )->epoch; };
        return $epoch;
    }
    return;
}

1;

__END__

=pod

=encoding utf8

=head1 NAME

GDPR::IAB::TCFv2::CMPValidator - IAB Registry-based CMP validation

=head1 SYNOPSIS

    use GDPR::IAB::TCFv2::CMPValidator;

    my $v = GDPR::IAB::TCFv2::CMPValidator->new(
        file => 't/corpus/cmp-list.json'
    );

    if ($v->is_valid(21)) {
        print "CMP 21 is valid and not deleted\n";
    }

=head1 DESCRIPTION

This module validates Consent Management Platform (CMP) IDs against the IAB TCF Registry.

=head1 IMPORTANT: REFRESH POLICY

The library B<does not automatically refresh> the CMP list from the IAB. It is the responsibility of the calling application to fetch and reload the list (e.g., via a cron job or manual update method) to ensure compliance with the latest IAB registry.

=head1 METHODS

=head2 new

Constructor. Can take C<file>, C<url>, or C<data> to initialize the list.

=head2 load_from_file($path)

Load CMP list from a local JSON file.

=head2 load_from_url($url)

Fetch CMP list from a URL. Requires L<HTTP::Tiny> to be installed.

=head2 load_from_data($json)

Parse CMP list from a JSON string.

=head2 is_valid($cmp_id)

Returns true if the CMP ID exists in the registry and is not deleted (respects C<deletedDate>).

=head2 last_updated_epoch

Returns the epoch of the C<lastUpdated> field in the registry.

=head1 DEPENDENCIES

=over

=item * L<JSON::PP> (Core)

=item * L<Time::Piece> (Core)

=item * L<HTTP::Tiny> (Optional, for URL loading)

=back

=cut


=back

=cut
