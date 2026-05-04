package GDPR::IAB::TCFv2::Validator;

use strict;
use warnings;

use Carp qw<croak>;
use GDPR::IAB::TCFv2;
use GDPR::IAB::TCFv2::Validator::Result;

sub new {
    my ( $klass, %args ) = @_;

    my $self = {
        vendor_id                       => $args{vendor_id},
        consent_purpose_ids             => $args{consent_purpose_ids} || [],
        legitimate_interest_purpose_ids => $args{legitimate_interest_purpose_ids} || [],
        flexible_purpose_ids            => $args{flexible_purpose_ids} || [],
        check_disclosed_vendors         => $args{check_disclosed_vendors} || 0,
        strict                          => exists $args{strict} ? $args{strict} : 0,
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

    my $tc = ref($input) eq 'GDPR::IAB::TCFv2'
      ? $input
      : GDPR::IAB::TCFv2->Parse($input);

    my $vendor_id =
      exists $overrides{vendor_id} ? $overrides{vendor_id} : $self->{vendor_id};
    my $strict = exists $overrides{strict} ? $overrides{strict} : $self->{strict};
    my $check_disclosed =
      exists $overrides{check_disclosed_vendors}
      ? $overrides{check_disclosed_vendors}
      : $self->{check_disclosed_vendors};

    croak "missing vendor_id" unless defined $vendor_id;

    my @reasons;

    # Check Disclosed Vendors if segment exists and requested
    if ($check_disclosed) {
        if ( defined $tc->{disclosed_vendors_data} ) {
            unless ( $tc->disclosed_vendor($vendor_id) ) {
                push @reasons, "vendor $vendor_id not disclosed";
                return $self->_make_result( 0, \@reasons ) if $stop_on_first;
            }
        }
    }

    # Check Consent Purposes
    foreach my $pid ( @{ $self->{consent_purpose_ids} } ) {
        unless (
            $tc->is_vendor_consent_allowed( $vendor_id, $pid, strict => $strict )
          )
        {
            push @reasons,
              "vendor $vendor_id not allowed for purpose $pid (consent)";
            return $self->_make_result( 0, \@reasons ) if $stop_on_first;
        }
    }

    # Check Legitimate Interest Purposes
    foreach my $pid ( @{ $self->{legitimate_interest_purpose_ids} } ) {
        unless (
            $tc->is_vendor_legitimate_interest_allowed(
                $vendor_id, $pid, strict => $strict
            )
          )
        {
            push @reasons,
"vendor $vendor_id not allowed for purpose $pid (legitimate interest)";
            return $self->_make_result( 0, \@reasons ) if $stop_on_first;
        }
    }

    # Check Flexible Purposes
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
                $vendor_id, $pid, $default_is_li, strict => $strict
            )
          )
        {
            push @reasons, "vendor $vendor_id not allowed for flexible purpose $pid";
            return $self->_make_result( 0, \@reasons ) if $stop_on_first;
        }
    }

    if (@reasons) {
        return $self->_make_result( 0, \@reasons );
    }

    return $self->_make_result( 1, [] );
}

sub _make_result {
    my ( $self, $ok, $reasons ) = @_;

    return GDPR::IAB::TCFv2::Validator::Result->new(
        ok      => $ok,
        reasons => $reasons,
    );
}

1;
