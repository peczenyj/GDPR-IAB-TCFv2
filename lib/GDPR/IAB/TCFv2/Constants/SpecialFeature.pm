package GDPR::IAB::TCFv2::Constants::SpecialFeature;
use strict;
use warnings;

require Exporter;
use base qw<Exporter>;

use constant {
    Geolocation => 1,
    DeviceScan  => 2,
};

our @EXPORT_OK = qw<
  Geolocation
  DeviceScan
>;

our %EXPORT_TAGS = ( all => \@EXPORT_OK );

1;

__END__

=head1 NAME

GDPR::IAB::TCFv2::Constants::SpecialFeature - TCF v2.2 special features

=head1 SYNOPSIS

    use strict;
    use warnings;
    
    use GDPR::IAB::TCFv2::Constants::SpecialFeature qw<:all>;

    use feature 'say';
    
    say "Geolocation id is ". Geolocation;
    # Output:
    # Geolocation id is 1

=head1 CONSTANTS

=head2  Geolocation

Special feature id 1: Use precise geolocation data

With your acceptance, your precise location (within a radius of less than 500 metres) may be used in support of the purposes explained in this notice.

=head2  DeviceScan

Special feature id 2: Actively scan device characteristics for identification

With your acceptance, certain characteristics specific to your device might be requested and used to distinguish it from other devices (such as the installed fonts or plugins, the resolution of your screen) in support of the purposes explained in this notice.
      "description": 
