package iabtcfv2 0.510;

use v5.12;
use warnings;

use GDPR::IAB::TCFv2::Parser;
use GDPR::IAB::TCFv2::Validator;

use Exporter qw(import);

our @EXPORT = qw(tcf validator);

sub tcf       { GDPR::IAB::TCFv2::Parser->Parse(@_) }
sub validator { GDPR::IAB::TCFv2::Validator->new(@_) }

1;
__END__

=pod

=encoding utf8

=head1 NAME

iabtcfv2 - shortcut module for one-liner and shell use of GDPR::IAB::TCFv2

=head1 SYNOPSIS

    use feature qw<say>;
    use iabtcfv2;

    my $tc_string = 'CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA';

    # Parse a TC string and inspect:
    my $c = tcf($tc_string);
    say $c->cmp_id;
    say $c->consent_language;

    # Validate:
    my $r = validator(
        vendor_id           => 284,
        consent_purpose_ids => [ 1, 3 ],
    )->validate($tc_string);
    say $r ? "ok" : "fail: $r";

    # One-liner from the shell:
    #   perl -Miabtcfv2 -E 'say tcf(shift)->cmp_id' "$tc"

=head1 DESCRIPTION

C<iabtcfv2> is a pure-exporter shortcut module for one-liner and
shell use of the C<GDPR-IAB-TCFv2> distribution. It exports two
constructor shortcuts so that C<perl -Miabtcfv2 -E '...'> can write
C<tcf($s)> and C<validator(%opts)> instead of the full-namespace
forms.

C<iabtcfv2> is intentionally B<not> an inheritance hub: there is no
C<@ISA>, and class-method calls like C<< iabtcfv2->Parse(...) >> are
deliberately not supported. Use C<tcf()> for one-liners, or call
C<< GDPR::IAB::TCFv2->Parse(...) >> on the hub for OO invocation in
full scripts.

For the full parser API see L<GDPR::IAB::TCFv2::Parser>. For
declarative validation see L<GDPR::IAB::TCFv2::Validator>. For
project overview see L<GDPR::IAB::TCFv2>.

=head1 EXPORTS

Both functions are exported automatically on C<use iabtcfv2;>.

=head2 tcf

    my $consent = tcf($tc_string);

Shortcut for C<< GDPR::IAB::TCFv2::Parser->Parse($tc_string) >>.
Returns a C<GDPR::IAB::TCFv2::Parser> instance.

=head2 validator

    my $v = validator(
        vendor_id           => 284,
        consent_purpose_ids => [ 1, 3 ],
    );

Shortcut for C<< GDPR::IAB::TCFv2::Validator->new(%opts) >>. Returns
a C<GDPR::IAB::TCFv2::Validator> instance. Pass to
C<< $v->validate($tc_string) >> for a fail-fast check.

=head1 SEE ALSO

L<GDPR::IAB::TCFv2>, L<GDPR::IAB::TCFv2::Parser>,
L<GDPR::IAB::TCFv2::Validator>.

The IAB TCF v2 specification:
L<https://github.com/InteractiveAdvertisingBureau/GDPR-Transparency-and-Consent-Framework/blob/master/TCFv2/IAB%20Tech%20Lab%20-%20Consent%20string%20and%20vendor%20list%20formats%20v2.md>.

=head1 AUTHOR

Tiago Peczenyj L<mailto:tiago.peczenyj+cpan@gmail.com>

=head1 LICENSE AND COPYRIGHT

Copyright 2023-2026 Tiago Peczenyj.

This program is free software; you can redistribute it and/or modify
it under the terms of either: the GNU General Public License as
published by the Free Software Foundation; or the Artistic License.

=cut
