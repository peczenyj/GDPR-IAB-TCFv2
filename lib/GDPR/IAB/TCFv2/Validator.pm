package GDPR::IAB::TCFv2::Validator;

use strict;
use warnings;

use Carp         qw<croak>;
use Scalar::Util qw<blessed>;
use GDPR::IAB::TCFv2;
use GDPR::IAB::TCFv2::Validator::Failure;
use GDPR::IAB::TCFv2::Validator::Reason qw<:all>;
use GDPR::IAB::TCFv2::Validator::Result;

sub new {
    my ( $klass, %args ) = @_;

    my $consent             = $args{consent_purpose_ids}             || [];
    my $legitimate_interest = $args{legitimate_interest_purpose_ids} || [];
    my $flexible            = $args{flexible_purpose_ids}            || [];

    _check_coherence( $consent, $legitimate_interest, $flexible );

    # Compute cmp_validator in scalar context so a bare `return` from the
    # coercer correctly yields undef -- a list-context call inside the
    # anonymous-hash construction below would collapse the key/value
    # pair instead.
    my $cmp_v = _coerce_cmp_validator( $args{cmp_validator} );

    my $self = {
        vendor_id                       => $args{vendor_id},
        consent_purpose_ids             => $consent,
        legitimate_interest_purpose_ids => $legitimate_interest,
        flexible_purpose_ids            => $flexible,
        _flexible_set                   => { map { $_ => 1 } @{$flexible} },
        check_disclosed_vendors         => $args{check_disclosed_vendors} || 0,
        min_policy_version              => $args{min_policy_version},
        cmp_validator                   => $cmp_v,
        strict => exists $args{strict} ? $args{strict} : 0,
    };

    return bless $self, $klass;
}

# Accept either a CMPValidator object, a hashref of constructor args
# (auto-instantiated lazily on the first call), or undef.  Defer the
# `require` so callers who never opt into the CMP rule never pay for
# loading JSON::PP / Time::Piece.
sub _coerce_cmp_validator {
    my ($spec) = @_;

    # Bare `return` is fine -- callers always invoke this in scalar
    # context (see the explicit `my $cmp_v = ...` in `new` and the
    # `my $cmp_validator = ...` in `_run_validation`).
    return unless defined $spec;
    return $spec
      if blessed($spec) && $spec->isa('GDPR::IAB::TCFv2::CMPValidator');

    croak "cmp_validator must be a GDPR::IAB::TCFv2::CMPValidator object "
      . "or a hashref of constructor arguments"
      unless ref($spec) eq 'HASH';

    require GDPR::IAB::TCFv2::CMPValidator;
    return GDPR::IAB::TCFv2::CMPValidator->new( %{$spec} );
}

sub _check_coherence {
    my ( $consent, $legitimate_interest, $flexible ) = @_;

    my %consent_set = map { $_ => 1 } @{$consent};
    my %li_set      = map { $_ => 1 } @{$legitimate_interest};

    foreach my $pid ( @{$consent} ) {
        croak
          "purpose $pid cannot be in both consent_purpose_ids and legitimate_interest_purpose_ids"
          if $li_set{$pid};
    }

    foreach my $pid ( @{$flexible} ) {
        next if $consent_set{$pid} || $li_set{$pid};
        croak
          "flexible purpose $pid must also appear in consent_purpose_ids or legitimate_interest_purpose_ids";
    }

    return;
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
    my $min_policy_version =
      exists $overrides{min_policy_version}
      ? $overrides{min_policy_version}
      : $self->{min_policy_version};
    my $cmp_validator =
      exists $overrides{cmp_validator}
      ? _coerce_cmp_validator( $overrides{cmp_validator} )
      : $self->{cmp_validator};

    croak "missing vendor_id" unless defined $vendor_id;

    my @failures;

    $self->_check_min_policy_version( $tc, $min_policy_version, \@failures );
    return $self->_make_result( 0, \@failures )
      if $stop_on_first && @failures;

    $self->_check_cmp_validator( $tc, $cmp_validator, \@failures );
    return $self->_make_result( 0, \@failures )
      if $stop_on_first && @failures;

    $self->_check_disclosed( $tc, $vendor_id, $check_disclosed, \@failures );
    return $self->_make_result( 0, \@failures )
      if $stop_on_first && @failures;

    $self->_check_consent_purposes(
        $tc, $vendor_id, $strict, \@failures,
        $stop_on_first
    );
    return $self->_make_result( 0, \@failures )
      if $stop_on_first && @failures;

    $self->_check_li_purposes(
        $tc, $vendor_id, $strict, \@failures,
        $stop_on_first
    );

    if (@failures) {
        return $self->_make_result( 0, \@failures );
    }

    return $self->_make_result( 1, [] );
}

sub _check_cmp_validator {
    my ( $self, $tc, $cmp_validator, $failures ) = @_;

    return unless defined $cmp_validator;

    my $cmp_id = $tc->cmp_id;
    unless ( $cmp_validator->is_valid($cmp_id) ) {
        push @{$failures},
          GDPR::IAB::TCFv2::Validator::Failure->new(
            code    => ReasonInvalidCMP,
            message => "CMP $cmp_id is not valid/disclosed",
            cmp_id  => $cmp_id,
          );
    }
    return;
}

sub _check_min_policy_version {
    my ( $self, $tc, $min_policy_version, $failures ) = @_;

    return unless defined $min_policy_version;

    my $actual = $tc->policy_version;
    if ( $actual < $min_policy_version ) {
        push @{$failures},
          GDPR::IAB::TCFv2::Validator::Failure->new(
            code    => ReasonPolicyVersionTooLow,
            message =>
              "TC string policy version $actual is below required minimum $min_policy_version",
          );
    }
    return;
}

sub _check_disclosed {
    my ( $self, $tc, $vendor_id, $check_disclosed, $failures ) = @_;

    return unless $check_disclosed;
    return unless $tc->has_vendor_disclosure;

    unless ( $tc->disclosed_vendor($vendor_id) ) {
        push @{$failures},
          GDPR::IAB::TCFv2::Validator::Failure->new(
            code      => ReasonVendorNotDisclosed,
            message   => "vendor $vendor_id not disclosed",
            vendor_id => $vendor_id,
          );
    }
    return;
}

sub _check_consent_purposes {
    my ( $self, $tc, $vendor_id, $strict, $failures, $stop_on_first ) = @_;

    foreach my $pid ( @{ $self->{consent_purpose_ids} } ) {
        my $allowed = $self->{_flexible_set}->{$pid}
          ? $tc->is_vendor_allowed_for_flexible_purpose(
            $vendor_id, $pid, 0,
            strict => $strict
          )
          : $tc->is_vendor_consent_allowed(
            $vendor_id, $pid,
            strict => $strict
          );

        unless ($allowed) {
            push @{$failures},
              GDPR::IAB::TCFv2::Validator::Failure->new(
                code    => ReasonVendorNotAllowedConsent,
                message =>
                  "vendor $vendor_id not allowed for purpose $pid (consent)",
                purpose_id => $pid,
                vendor_id  => $vendor_id,
              );
            return if $stop_on_first;
        }
    }
    return;
}

sub _check_li_purposes {
    my ( $self, $tc, $vendor_id, $strict, $failures, $stop_on_first ) = @_;

    foreach my $pid ( @{ $self->{legitimate_interest_purpose_ids} } ) {
        my $allowed = $self->{_flexible_set}->{$pid}
          ? $tc->is_vendor_allowed_for_flexible_purpose(
            $vendor_id, $pid, 1,
            strict => $strict
          )
          : $tc->is_vendor_legitimate_interest_allowed(
            $vendor_id, $pid,
            strict => $strict
          );

        unless ($allowed) {
            push @{$failures},
              GDPR::IAB::TCFv2::Validator::Failure->new(
                code    => ReasonVendorNotAllowedLegitimateInterest,
                message =>
                  "vendor $vendor_id not allowed for purpose $pid (legitimate interest)",
                purpose_id => $pid,
                vendor_id  => $vendor_id,
              );
            return if $stop_on_first;
        }
    }
    return;
}


sub _make_result {
    my ( $self, $ok, $failures ) = @_;

    return GDPR::IAB::TCFv2::Validator::Result->new(
        ok       => $ok,
        failures => $failures,
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
        flexible_purpose_ids            => [ 10 ],
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

C<flexible_purpose_ids> — arrayref of purpose IDs that are B<flexible> per
the vendor's GVL declaration (the basis can flip if a publisher restriction
is present in the TC string). The default basis is derived structurally
from the other two lists:

=over 8

=item *

If the purpose ID also appears in C<consent_purpose_ids>, the default basis
is consent.

=item *

If the purpose ID also appears in C<legitimate_interest_purpose_ids>, the
default basis is legitimate interest.

=back

A purpose listed in C<flexible_purpose_ids> must also appear in exactly one
of the other two lists, or the constructor C<croak>s. Validated via
L<GDPR::IAB::TCFv2/is_vendor_allowed_for_flexible_purpose>.

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
