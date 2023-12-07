package GDPR::IAB::TCFv2::Constants::RestrictionType;
use strict;
use warnings;
use Scalar::Util qw<dualvar>;

require Exporter;
use base qw<Exporter>;

use constant {
    NotAllowed     => dualvar( 0, "Purpose Flatly Not Allowed by Publisher" ),
    RequireConsent => dualvar( 1, "Require Consent" ),
    RequireLegitimateInterest => dualvar( 2, "Require Legitimate Interest" ),
};

our @EXPORT_OK = qw<
  NotAllowed
  RequireConsent
  RequireLegitimateInterest
>;

our %EXPORT_TAGS = ( all => \@EXPORT_OK );

1;

__END__

=head1 NAME

GDPR::IAB::TCFv2::Constants::RestrictionType - TCF v2.2 publisher retriction type for vendor 

=head1 SYNOPSIS

    use strict;
    use warnings;
    
    use GDPR::IAB::TCFv2::Constants::RestrictionType qw<:all>;

    use feature 'say';
    
    say "Restriction type id is ". (0+NotAllowed), ", and it means " . NotAllowed;
    # Output:
    # Restriction type id is 0, and it means Purpose Flatly Not Allowed by Publisher

=head1 CONSTANTS

All constants are C<dualvar> (see L<Scalar::Util>).

Returns a scalar that has the C<id> in a numeric context and the C<description> in a string context.

=head2  NotAllowed

Restriction type id 0:  Purpose Flatly Not Allowed by Publisher (regardless of Vendor declarations).

=head2  RequireConsent

Restriction type id 1: Require Consent (if Vendor has declared the Purpose IDs legal basis as Legitimate Interest and flexible)

=head2 RequireLegitimateInterest

Restriction type id 2: Require Legitimate Interest (if Vendor has declared the Purpose IDs legal basis as Consent and flexible)

=head1 NOTE

Vendors must always respect a 0 (Not Allowed) regardless of whether or not they have not declared that Purpose to be "flexible". Values 1 and 2 are in accordance with a vendor's declared flexibility. Eg. if a vendor has Purpose 2 declared as Legitimate Interest but also declares that Purpose as flexible and this field is set to 1, they must then check for the "consent" signal in the VendorConsents section to make a determination on whether they have the legal basis for processing user personal data under that Purpose.

When a vendor's Purpose registration is not flexible they should interpret this value in the following ways:

If this value is 1 and vendor is registered under Legitimate Interest for that Purpose then the vendor should not process for that Purpose.

If this value is 1 and vendor is registered under Consent for that Purpose then the vendor can ignore the signal.

If this value is 2 and vendor is registered under Consent for that Purpose then the vendor should not process for that Purpose.

If this value is 2 and vendor is registered under Legitimate Interest for that Purpose then the vendor can ignore the signal.

If this value is 1 or 2 and the vendor is not registered for the Purpose then the vendor should not process for that Purpose.

Note: Purpose 1 is always required to be registered as a consent purpose and can not be flexible per L<Policies|https://iabeurope.eu/iab-europe-transparency-consent-framework-policies/>.
