use strict;
use warnings;
use Test::More;
use lib 'lib';

use GDPR::IAB::TCFv2::Validator;
use GDPR::IAB::TCFv2::Validator::Reason qw<:all>;

# These tests pin the Perl Validator to the Go lib-gdpr "redesign" branch
# strict-path semantics (validator/validator_strict.go + the surrounding
# gates in validator/validator.go). Each subtest names the Go construct it
# mirrors.

# A lightweight TC stub exposing only the accessors the rule methods consult,
# so the date-based / policy-based gates are deterministic and independent of
# any fixture string.
{

  package TCStub;
  sub new                   { my ($c, %a) = @_; return bless {%a}, $c }
  sub created               { return $_[0]->{created} }
  sub policy_version        { return $_[0]->{pv} }
  sub has_vendor_disclosure { return $_[0]->{dv} }
  sub disclosed_vendor      { return $_[0]->{disclosed} }
}

use constant DEADLINE => 1772236800;    # 2026-02-28T00:00:00Z

subtest '#1 min>=5 auto-enables verify_disclosed (Go New: ||= min>=5)' => sub {
  my $v = GDPR::IAB::TCFv2::Validator->new(vendor_id => 10, min_tcf_policy_version => 5);

  ok $v->{verify_disclosed_vendors}, 'min_tcf_policy_version >= 5 auto-enables verify_disclosed_vendors';

  my $v4 = GDPR::IAB::TCFv2::Validator->new(vendor_id => 10, min_tcf_policy_version => 4);
  ok !$v4->{verify_disclosed_vendors}, 'min_tcf_policy_version < 5 leaves verify_disclosed_vendors off';
};

subtest '#1 mandatory DV runs regardless of verify_disclosed (Go yieldMandatoryDisclosedVendors)' => sub {
  my $v = GDPR::IAB::TCFv2::Validator->new(vendor_id => 10);

  # policy 5 string, DV absent, pre-deadline, min floor 5, verify explicitly OFF.
  # Go's mandatory-DV (branch b) fires independent of verifyDisclosedVendors.
  my @f;
  my $tc = TCStub->new(created => DEADLINE - 1, pv => 5, dv => 0);
  $v->_check_disclosed($tc, 10, 0, 5, \@f);

  my %c = map { $_->code => 1 } @f;
  ok $c{ReasonMissingDisclosedVendors()},
    'policy>=5 && min>=5 && DV absent => MissingDisclosedVendors even with verify off';
};

subtest '#1 verify auto-enable surfaces VendorNotDisclosed when DV present' => sub {
  my $v = GDPR::IAB::TCFv2::Validator->new(vendor_id => 10, min_tcf_policy_version => 5);

  # DV segment present, vendor 10 NOT disclosed, pre-deadline.
  my @f;
  my $tc = TCStub->new(created => DEADLINE - 1, pv => 5, dv => 1, disclosed => 0);
  $v->_check_disclosed($tc, 10, $v->{verify_disclosed_vendors}, 5, \@f);

  my %c = map { $_->code => 1 } @f;
  ok $c{ReasonVendorNotDisclosed()}, 'min>=5 auto-enables verify => undisclosed vendor fails';
};

subtest '#2 policy-based MissingDV requires the string policy>=5 (Go branch b)' => sub {
  my $v = GDPR::IAB::TCFv2::Validator->new(vendor_id => 10);

  # min floor 5, verify ON, but the STRING is policy 2 and DV absent, pre-deadline.
  # Go branch (b) needs string policy>=5, so it must NOT emit MissingDisclosedVendors.
  my @f;
  my $tc = TCStub->new(created => DEADLINE - 1, pv => 2, dv => 0);
  $v->_check_disclosed($tc, 10, 1, 5, \@f);

  my %c = map { $_->code => 1 } @f;
  ok !$c{ReasonMissingDisclosedVendors()}, 'policy<5 string does not trigger the policy-based MissingDisclosedVendors';
};

subtest '#5 single PolicyVersionTooLow even when both the v2.3 and floor rules apply' => sub {
  my $v = GDPR::IAB::TCFv2::Validator->new(vendor_id => 10);

  # Post-deadline, policy 2, floor 5: Go's combined policy gate yields exactly
  # one ReasonPolicyVersionTooLow (v2.3 rule wins, then returns).
  my @f;
  my $tc = TCStub->new(created => DEADLINE, pv => 2, dv => 1);
  $v->_check_policy_version($tc, 5, \@f);

  my @pv = grep { $_->code == ReasonPolicyVersionTooLow } @f;
  is scalar(@pv), 1, 'exactly one PolicyVersionTooLow when v2.3 + floor both apply';
};

subtest '#3 flexible purpose + NotAllowed restriction => ReasonPublisherRestrictionNotAllowed' => sub {

  # Mirrors Go runFlexibleCheck: a NotAllowed restriction on a flexible purpose
  # surfaces the dedicated publisher-restriction reason, not the generic
  # vendor-not-allowed reason.
  {

    package FlexNotAllowedStub;
    sub new                                    { return bless {}, shift }
    sub is_vendor_allowed_for_flexible_purpose { return 0 }

    # NotAllowed == 0; report it for any (purpose, vendor) pair.
    sub check_publisher_restriction { my (undef, undef, $type) = @_; return $type == 0 ? 1 : 0 }
  }

  my $v = GDPR::IAB::TCFv2::Validator->new(vendor_id => 7);

  my @f;
  $v->_check_consent_purposes(FlexNotAllowedStub->new, 7, 0, \@f, 0, [5], {5 => 1});

  is scalar(@f),  1,                                    'one failure for the flexible purpose';
  is $f[0]->code, ReasonPublisherRestrictionNotAllowed, 'flexible NotAllowed => ReasonPublisherRestrictionNotAllowed';
  is $f[0]->restriction_type, 0,                        'restriction_type is 0 (NotAllowed)';
  is $f[0]->purpose_id,       5,                        'purpose_id preserved';
  is $f[0]->vendor_id,        7,                        'vendor_id preserved';
};

subtest '#3 flexible purpose + NotAllowed on LI basis => ReasonPublisherRestrictionNotAllowed' => sub {
  {

    package FlexNotAllowedStubLI;
    sub new                                    { return bless {}, shift }
    sub policy_version                         { return 5 }
    sub is_vendor_allowed_for_flexible_purpose { return 0 }
    sub check_publisher_restriction            { my (undef, undef, $type) = @_; return $type == 0 ? 1 : 0 }
  }

  my $v = GDPR::IAB::TCFv2::Validator->new(vendor_id => 7);

  my @f;
  $v->_check_li_purposes(FlexNotAllowedStubLI->new, 7, 0, \@f, 0, [9], {9 => 1});

  is scalar(@f), 1, 'one failure for the flexible LI purpose';
  is $f[0]->code, ReasonPublisherRestrictionNotAllowed,
    'flexible NotAllowed (LI default) => PublisherRestrictionNotAllowed';
};

done_testing;
