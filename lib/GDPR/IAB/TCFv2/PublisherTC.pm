package GDPR::IAB::TCFv2::PublisherTC;
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

use constant {
    SEGMENT_TYPE_PUBLISHER_TC => 3,
    MAX_PURPOSE_ID            => 24,
    OFFSETS                   => {
        SEGMENT_TYPE            => 0,
        PURPOSE_CONSENT_ALLOWED => 3,
        PURPOSE_LIT_ALLOWED     => 27,
        NUM_CUSTOM_PURPOSES     => 51,
        CUSTOM_PURPOSES_CONSENT => 57,
    },
};

sub Parse {
    my ( $klass, %args ) = @_;

    croak "missing 'data'"      unless defined $args{data};
    croak "missing 'data_size'" unless defined $args{data_size};

    croak "missing 'options'"      unless defined $args{options};
    croak "missing 'options.json'" unless defined $args{options}->{json};

    my $data      = $args{data};
    my $data_size = $args{data_size};
    my $options   = $args{options};

    croak "invalid min size" if $data_size < 57;

    my $segment_type = get_uint3( $data, OFFSETS->{SEGMENT_TYPE} );

    croak
      "invalid segment type ${segment_type}: expected @{[ SEGMENT_TYPE_PUBLISHER_TC ]}"
      if $segment_type != SEGMENT_TYPE_PUBLISHER_TC;

    my $num_custom_purposes =
      get_uint6( $data, OFFSETS->{NUM_CUSTOM_PURPOSES} );

    my $total_expected_size = 2 * $num_custom_purposes + 57;

    croak "invalid size" if $data_size < $total_expected_size;

    my $self = {
        data                      => $data,
        options                   => $options,
        num_custom_purposes       => $num_custom_purposes,
        custom_purpose_lit_offset => OFFSETS->{CUSTOM_PURPOSES_CONSENT}
          + $num_custom_purposes,
    };

    bless $self, $klass;

    return $self;
}

sub num_custom_purposes {
    my $self = shift;

    return $self->{num_custom_purposes};
}

sub is_purpose_consent_allowed {
    my ( $self, $id ) = @_;

    croak "invalid purpose id $id: must be between 1 and @{[ MAX_PURPOSE_ID ]}"
      if $id < 1 || $id > MAX_PURPOSE_ID;

    return $self->_safe_is_purpose_consent_allowed($id);
}

sub is_purpose_legitimate_interest_allowed {
    my ( $self, $id ) = @_;

    croak "invalid purpose id $id: must be between 1 and @{[ MAX_PURPOSE_ID ]}"
      if $id < 1 || $id > MAX_PURPOSE_ID;

    return $self->_safe_is_purpose_legitimate_interest_allowed($id);
}

sub is_custom_purpose_consent_allowed {
    my ( $self, $id ) = @_;

    croak
      "invalid custom purpose id $id: must be between 1 and @{[ $self->{num_custom_purposes} ]}"
      if $id < 1 || $id > $self->{num_custom_purposes};

    return $self->_safe_is_custom_purpose_consent_allowed($id);
}

sub is_custom_purpose_legitimate_interest_allowed {
    my ( $self, $id ) = @_;

    croak
      "invalid custom purpose id $id: must be between 1 and @{[ $self->{num_custom_purposes} ]}"
      if $id < 1 || $id > $self->{num_custom_purposes};

    return $self->_safe_is_custom_purpose_legitimate_interest_allowed($id);
}

sub TO_JSON {
    my $self = shift;

    my %consents = map { $_ => $self->_safe_is_purpose_consent_allowed($_) }
      1 .. MAX_PURPOSE_ID;
    my %legitimate_interests =
      map { $_ => $self->_safe_is_purpose_legitimate_interest_allowed($_) }
      1 .. MAX_PURPOSE_ID;
    my %custom_purpose_consents =
      map { $_ => $self->_safe_is_custom_purpose_consent_allowed($_) }
      1 .. $self->{num_custom_purposes};
    my %custom_purpose_legitimate_interests = map {
        $_ => $self->_safe_is_custom_purpose_legitimate_interest_allowed($_)
    } 1 .. $self->{num_custom_purposes};

    return {
        consents =>
          $self->_format_json_subsection( \%consents, MAX_PURPOSE_ID ),
        legitimate_interests => $self->_format_json_subsection(
            \%legitimate_interests, MAX_PURPOSE_ID
        ),
        custom_purpose => {
            consents => $self->_format_json_subsection(
                \%custom_purpose_consents, $self->{num_custom_purposes}
            ),
            legitimate_interests => $self->_format_json_subsection(
                \%custom_purpose_legitimate_interests,
                $self->{num_custom_purposes}
            ),
        },
    };
}

sub _format_json_subsection {
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

sub _safe_is_purpose_consent_allowed {
    my ( $self, $id ) = @_;
    return
      scalar(
        is_set( $self->{data}, OFFSETS->{PURPOSE_CONSENT_ALLOWED} + $id - 1 )
      );
}

sub _safe_is_purpose_legitimate_interest_allowed {
    my ( $self, $id ) = @_;

    return
      scalar(
        is_set( $self->{data}, OFFSETS->{PURPOSE_LIT_ALLOWED} + $id - 1 ) );
}

sub _safe_is_custom_purpose_consent_allowed {
    my ( $self, $id ) = @_;
    return
      scalar(
        is_set( $self->{data}, OFFSETS->{CUSTOM_PURPOSES_CONSENT} + $id - 1 )
      );
}

sub _safe_is_custom_purpose_legitimate_interest_allowed {
    my ( $self, $id ) = @_;

    return
      scalar(
        is_set( $self->{data}, $self->{custom_purpose_lit_offset} + $id - 1 )
      );
}

# add method TO_JSON

1;
