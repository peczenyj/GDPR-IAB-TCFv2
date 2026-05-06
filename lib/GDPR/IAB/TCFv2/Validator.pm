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
        legitimate_interest_purpose_ids =>
          $args{legitimate_interest_purpose_ids} || [],
        flexible_purpose_ids    => $args{flexible_purpose_ids}    || [],
        check_disclosed_vendors => $args{check_disclosed_vendors} || 0,
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

    croak "missing vendor_id" unless defined $vendor_id;

    my @reasons;

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

sub _check_disclosed {
    my ( $self, $tc, $vendor_id, $check_disclosed, $reasons ) = @_;

    return unless $check_disclosed;
    return unless $tc->has_vendor_disclosure;

    unless ( $tc->disclosed_vendor($vendor_id) ) {
        push @{$reasons}, "vendor $vendor_id not disclosed";
    }
    return;
}

sub _check_consent_purposes {
    my ( $self, $tc, $vendor_id, $strict, $reasons, $stop_on_first ) = @_;

    foreach my $pid ( @{ $self->{consent_purpose_ids} } ) {
        unless (
            $tc->is_vendor_consent_allowed(
                $vendor_id, $pid, strict => $strict
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
                $vendor_id, $pid, strict => $strict
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
                $vendor_id, $pid, $default_is_li, strict => $strict
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

=encoding utf8

=head1 NAME

GDPR::IAB::TCFv2::Validator - declarative compliance checks for TC strings

=head1 SYNOPSIS

    use GDPR::IAB::TCFv2::Validator;

    my $validator = GDPR::IAB::TCFv2::Validator->new(
        vendor_id                       => 284,
        consent_purpose_ids             => [ 1, 3, 9 ],
        legitimate_interest_purpose_ids => [ 10 ],
        flexible_purpose_ids            => [
            { purpose_id => 2, default_is_li => 1 },
        ],
        check_disclosed_vendors         => 1,
    );

    # Fail-fast: stops at the first failing rule.
    my $result = $validator->validate($tc_string);

    # Accumulate every failure for richer error reporting.
    my $result = $validator->validate_all($tc_string);

    if ($result) {
        # All rules passed.
    }
    else {
        warn "Compliance failed:\n$result\n";  # stringification = reasons
        for my $reason ( $result->reasons ) {
            log_failure($reason);
        }
    }

=head1 DESCRIPTION

C<GDPR::IAB::TCFv2::Validator> is a small rule engine that turns a static
"compliance policy" — required purposes, expected vendor, optional
disclosed-vendors check — into a single C<validate> / C<validate_all>
call against a TC string (or a pre-parsed L<GDPR::IAB::TCFv2> object).

Each rule produces a human-readable B<reason> on failure; reasons are
collected on a L<GDPR::IAB::TCFv2::Validator::Result> object that
overloads boolean and string contexts so it drops into typical
error-handling idioms (C<if (!$result)>, C<print "$result\n">) without
ceremony.

=head1 CONSTRUCTOR

=head2 new

    my $v = GDPR::IAB::TCFv2::Validator->new( %args );

Recognized keys:

=over 4

=item *

C<vendor_id> — the vendor whose access is being validated. Optional in
the constructor (can be supplied per call via C<< validate(..., vendor_id
=> N) >>) but B<one of the two> must be set or C<validate>/C<validate_all>
will C<croak> with C<"missing vendor_id">.

=item *

C<consent_purpose_ids> — arrayref of purpose IDs that B<must> have
vendor consent. Validated via L<GDPR::IAB::TCFv2/is_vendor_consent_allowed>.

=item *

C<legitimate_interest_purpose_ids> — arrayref of purpose IDs that B<must>
have vendor legitimate-interest. Validated via
L<GDPR::IAB::TCFv2/is_vendor_legitimate_interest_allowed>. The IAB spec
forbids LI for Purpose 1 always, and for Purposes 3-6 in TCF v2.2+;
those are enforced by the underlying parser and surface here as failures.

=item *

C<flexible_purpose_ids> — arrayref of either:

=over 8

=item *

a plain integer (purpose ID, default legal basis = consent), or

=item *

a hashref C<< { purpose_id => N, default_is_li => 0|1 } >> for explicit
control over the default legal basis.

=back

Validated via L<GDPR::IAB::TCFv2/is_vendor_allowed_for_flexible_purpose>.

=item *

C<check_disclosed_vendors> — boolean. When true B<and> the TC string
carries a Disclosed Vendors segment, the vendor must appear there or
the rule fails with C<"vendor N not disclosed">. If the segment is
absent the check is silently skipped — set the parser's C<strict>
mode at parse time if you need to require the segment's presence.

=item *

C<strict> — boolean. Passed through to the underlying
C<is_vendor_*_allowed> calls so invalid purpose IDs cause C<croak>
instead of a silent failure.

=back

=head1 METHODS

=head2 validate

    my $result = $validator->validate( $tc_string_or_object, %overrides );

Runs the configured rules against C<$tc_string_or_object>. Stops at
the first failing rule (B<fail-fast> mode) and returns a
L<GDPR::IAB::TCFv2::Validator::Result> carrying that one reason.

C<%overrides> can replace the constructor values for C<vendor_id>,
C<strict>, and C<check_disclosed_vendors> for this call only. The
arrayref rules (C<consent_purpose_ids> etc.) are not currently
overridable per call.

C<$tc_string_or_object> may be either a raw consent string or a
pre-parsed L<GDPR::IAB::TCFv2> object — handy when the same TC string
is being validated against multiple policies.

=head2 validate_all

Identical to L</validate> but runs B<every> rule and accumulates all
failures into the result. Use when you want a complete error report
rather than the first failure.

=head1 SEE ALSO

L<GDPR::IAB::TCFv2::Validator::Result> for the result-object API,
including the C<bool> / C<""> overloads and the C<$\>-aware
stringification.

L<GDPR::IAB::TCFv2> for the underlying parser and the
C<is_vendor_*_allowed> family of methods this validator is built on.

=cut
