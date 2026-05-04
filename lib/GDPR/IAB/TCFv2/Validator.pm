package GDPR::IAB::TCFv2::Validator;

use strict;
use warnings;

use Carp qw<croak>;
use GDPR::IAB::TCFv2;
use GDPR::IAB::TCFv2::Validator::Result;
use GDPR::IAB::TCFv2::CMPValidator;

sub new {
    my ( $klass, %args ) = @_;

    my $cmp_validator = $args{cmp_validator};
    if ( defined $cmp_validator && ref $cmp_validator eq 'HASH' ) {
        $cmp_validator = GDPR::IAB::TCFv2::CMPValidator->new(%$cmp_validator);
    }

    my $self = {
        vendor_id                       => $args{vendor_id},
        consent_purpose_ids             => $args{consent_purpose_ids} || [],
        legitimate_interest_purpose_ids =>
          $args{legitimate_interest_purpose_ids} || [],
        flexible_purpose_ids    => $args{flexible_purpose_ids}    || [],
        check_disclosed_vendors => $args{check_disclosed_vendors} || 0,
        cmp_validator           => $cmp_validator,
        strict                  => exists $args{strict} ? $args{strict} : 0,
    };

    return bless $self, $klass;
}

sub validate {
    my ( $self, $input, %overrides ) = @_;

    return $self->_run_validation( $input, 1, %overrides );
}

sub validate_all {
    my ( $self, $input, %overrides ) = @_;

    return $self->_run_validation( $input, 0, %overrides );
}

sub _run_validation {
    my ( $self, $input, $stop_on_first, %overrides ) = @_;

    my $tc =
      ref($input) eq 'GDPR::IAB::TCFv2'
      ? $input
      : GDPR::IAB::TCFv2->Parse($input);

    my $vendor_id =
      exists $overrides{vendor_id}
      ? $overrides{vendor_id}
      : $self->{vendor_id};
    my $strict =
      exists $overrides{strict} ? $overrides{strict} : $self->{strict};
    my $check_disclosed =
      exists $overrides{check_disclosed_vendors}
      ? $overrides{check_disclosed_vendors}
      : $self->{check_disclosed_vendors};
    my $cmp_validator =
      exists $overrides{cmp_validator}
      ? $overrides{cmp_validator}
      : $self->{cmp_validator};

    if ( defined $cmp_validator && ref $cmp_validator eq 'HASH' ) {
        $cmp_validator = GDPR::IAB::TCFv2::CMPValidator->new(%$cmp_validator);
    }

    croak "missing vendor_id" unless defined $vendor_id;

    my @reasons;

    $self->_check_cmp( $tc, $cmp_validator, \@reasons );
    return $self->_make_result( 0, \@reasons ) if $stop_on_first && @reasons;

    $self->_check_disclosed( $tc, $vendor_id, $check_disclosed, \@reasons );
    return $self->_make_result( 0, \@reasons ) if $stop_on_first && @reasons;

    $self->_check_consent_purposes(
        $tc, $vendor_id, $strict, \@reasons,
        $stop_on_first
    );
    return $self->_make_result( 0, \@reasons ) if $stop_on_first && @reasons;

    $self->_check_li_purposes(
        $tc, $vendor_id, $strict, \@reasons,
        $stop_on_first
    );
    return $self->_make_result( 0, \@reasons ) if $stop_on_first && @reasons;

    $self->_check_flexible_purposes(
        $tc, $vendor_id, $strict, \@reasons,
        $stop_on_first
    );

    if (@reasons) {
        return $self->_make_result( 0, \@reasons );
    }

    return $self->_make_result( 1, [] );
}

sub _check_cmp {
    my ( $self, $tc, $cmp_validator, $reasons ) = @_;

    if ($cmp_validator) {
        my $cmp_id = $tc->cmp_id;
        unless ( $cmp_validator->is_valid($cmp_id) ) {
            push @{$reasons}, "CMP $cmp_id is not valid/disclosed";
        }
    }
    return;
}

sub _check_disclosed {
    my ( $self, $tc, $vendor_id, $check_disclosed, $reasons ) = @_;

    if ($check_disclosed) {
        if ( defined $tc->{disclosed_vendors_data} ) {
            unless ( $tc->disclosed_vendor($vendor_id) ) {
                push @{$reasons}, "vendor $vendor_id not disclosed";
            }
        }
    }
    return;
}

sub _check_consent_purposes {
    my ( $self, $tc, $vendor_id, $strict, $reasons, $stop_on_first ) = @_;

    foreach my $pid ( @{ $self->{consent_purpose_ids} } ) {
        unless (
            $tc->is_vendor_consent_allowed(
                $vendor_id, $pid, { strict => $strict }
            )
          )
        {
            push @{$reasons},
              "vendor $vendor_id not allowed for purpose $pid (consent)";
            return if $stop_on_first;
        }
    }
    return;
}

sub _check_li_purposes {
    my ( $self, $tc, $vendor_id, $strict, $reasons, $stop_on_first ) = @_;

    foreach my $pid ( @{ $self->{legitimate_interest_purpose_ids} } ) {
        unless (
            $tc->is_vendor_legitimate_interest_allowed(
                $vendor_id, $pid, { strict => $strict }
            )
          )
        {
            push @{$reasons},
              "vendor $vendor_id not allowed for purpose $pid (legitimate interest)";
            return if $stop_on_first;
        }
    }
    return;
}

sub _check_flexible_purposes {
    my ( $self, $tc, $vendor_id, $strict, $reasons, $stop_on_first ) = @_;

    foreach my $flex ( @{ $self->{flexible_purpose_ids} } ) {
        my ( $pid, $default_is_li );
        if ( ref($flex) eq 'HASH' ) {
            $pid           = $flex->{purpose_id};
            $default_is_li = $flex->{default_is_li};
        }
        else {
            $pid           = $flex;
            $default_is_li = 0;
        }

        unless (
            $tc->is_vendor_allowed_for_flexible_purpose(
                $vendor_id, $pid, $default_is_li, { strict => $strict }
            )
          )
        {
            push @{$reasons},
              "vendor $vendor_id not allowed for flexible purpose $pid";
            return if $stop_on_first;
        }
    }
    return;
}

sub _make_result {
    my ( $self, $ok, $reasons ) = @_;

    return GDPR::IAB::TCFv2::Validator::Result->new(
        ok      => $ok,
        reasons => $reasons,
    );
}

1;

__END__

=pod

=encoding utf8

=head1 NAME

GDPR::IAB::TCFv2::Validator - Rule-based TCF v2.0 TC String validation

=head1 SYNOPSIS

    use GDPR::IAB::TCFv2::Validator;

    my $validator = GDPR::IAB::TCFv2::Validator->new(
        vendor_id                       => 284,
        consent_purpose_ids             => [1, 3],
        legitimate_interest_purpose_ids => [2, 4],
        cmp_validator                   => { file => 't/corpus/cmp-list.json' }
    );

    my $result = $validator->validate($tc_string);

    if ($result) {
        print "Valid compliance string\n";
    } else {
        print "Failure reasons:\n", $result->reasons, "\n";
    }

=head1 DESCRIPTION

C<GDPR::IAB::TCFv2::Validator> provides a high-level interface for validating TC Strings against specific business and compliance rules.

=head1 METHODS

=head2 new

Constructor. Accepts the following arguments:

=over

=item * C<vendor_id>: The ID of the vendor to validate.

=item * C<consent_purpose_ids>: Array reference of purposes requiring consent.

=item * C<legitimate_interest_purpose_ids>: Array reference of purposes requiring legitimate interest.

=item * C<flexible_purpose_ids>: Array reference of purposes that can be either (or hashrefs with C<purpose_id> and C<default_is_li>).

=item * C<check_disclosed_vendors>: Boolean. If true, checks if the vendor was disclosed (requires TCF v2.3 segment).

=item * C<cmp_validator>: Optional. A L<GDPR::IAB::TCFv2::CMPValidator> object or a hashref config.

=item * C<strict>: Boolean. If true, parsing errors will throw exceptions.

=back

=head2 validate

Validate a TC String or L<GDPR::IAB::TCFv2> object. Returns a L<GDPR::IAB::TCFv2::Validator::Result> object (which evaluates to boolean in scalar context). Stops at the first failure.

=head2 validate_all

Similar to C<validate> but continues to check all rules and returns all failure reasons.

=head1 SEE ALSO

L<GDPR::IAB::TCFv2::Validator::Result>, L<GDPR::IAB::TCFv2::CMPValidator>.

=cut
