package GDPR::IAB::TCFv2;

use strict;
use warnings;
use integer;
use bytes;
use version; our $VERSION = version->declare('v0.0.4');

use feature 'state';

use GDPR::IAB::TCFv2::BitUtils qw(:all);
use GDPR::IAB::TCFv2::BitField;
use GDPR::IAB::TCFv2::RangeSection;
use MIME::Base64 qw<decode_base64>;
use Carp         qw<croak>;

sub CONSENT_STRING_TCF2_SEPARATOR {'.'}
sub CONSENT_STRING_TCF2_PREFIX    {'C'}
sub MIN_BYTE_SIZE                 {29}

# ABSTRACT: gdpr iab tcf v2 consent string parser

sub Parse {
    my ( $klass, $tc_string ) = @_;

    croak 'missing gdpr consent string' unless $tc_string;

    my $core_tc_string = _get_core_tc_string($tc_string);

    my $data = unpack 'B*', _decode_base64url($core_tc_string);

    croak "vendor consent strings are at least @{[ MIN_BYTE_SIZE ]} bytes long"
      if length($data) / 8 < MIN_BYTE_SIZE;

    my $self = {
        data           => $data,
        tc_string      => $tc_string,
        core_tc_string => $core_tc_string,
    };

    bless $self, $klass;

    croak 'consent string is not tcf version 2' unless $self->version == 2;

    croak 'invalid vendor list version' if $self->vendor_list_version == 0;

    my $vendor_consents;
    my $legitimate_interest_start;

    if ( $self->_is_vendor_consent_range_encoding ) {
        ( $vendor_consents, $legitimate_interest_start ) =
          $self->_parseRangeSection( $self->max_vendor_id_consent, 230 );
    }
    else {
        ( $vendor_consents, $legitimate_interest_start ) =
          $self->_parseBitField( $self->max_vendor_id_consent, 230 );
    }

    $self->{vendor_consents} = $vendor_consents;

    my $legitimate_interest_max_vendor =
      get_uint16( $self->{data}, $legitimate_interest_start );

    $self->{legitimate_interest_max_vendor} = $legitimate_interest_max_vendor;

    croak
      "invalid consent data: no legitimate interest start position (got $legitimate_interest_start +16 but @{[ length( $self->{data} ) ]})"
      if $legitimate_interest_start + 16 > length( $self->{data} );

    my $is_vendor_legitimate_interest_range =
      is_set( $data, $legitimate_interest_start + 16 );

    my $vendor_legitimate_interests;
    my $pub_restrict_start;

    if ($is_vendor_legitimate_interest_range) {
        ( $vendor_legitimate_interests, $pub_restrict_start ) =
          $self->_parseRangeSection(
            $self->max_vendor_id_legitimate_interest,
            $legitimate_interest_start + 17
          );
    }
    else {
        ( $vendor_legitimate_interests, $pub_restrict_start ) =
          $self->_parseBitField(
            $self->max_vendor_id_legitimate_interest,
            $legitimate_interest_start + 17
          );
    }

    $self->{vendor_legitimate_interests} = $vendor_legitimate_interests;

    return $self;
}

sub _get_core_tc_string {
    my $tc_string = shift;

    my $pos = index( $tc_string, CONSENT_STRING_TCF2_SEPARATOR );

    return $tc_string if $pos < 0;

    return substr( $tc_string, 0, $pos );
}

sub _decode_base64url {
    my $s = shift;

    state $decode_base64url = MIME::Base64->can("decode_base64url") || sub {
        my $s = shift;
        $s =~ tr[-_][+/];
        $s .= '=' while length($s) % 4;
        return decode_base64($s);
    };

    return $decode_base64url->($s);
}

sub version {
    my $self = shift;

    return get_uint6( $self->{data}, 0 );
}

sub created {
    my $self = shift;

    my $deciseconds = get_uint36( $self->{data}, 6 );

    return $deciseconds / 10;
}

sub last_updated {
    my $self = shift;

    my $deciseconds = get_uint36( $self->{data}, 42 );

    return $deciseconds / 10;
}

sub cmp_id {
    my $self = shift;

    return get_uint12( $self->{data}, 78 );
}

sub cmp_version {
    my $self = shift;

    return get_uint12( $self->{data}, 90 );
}

sub consent_screen {
    my $self = shift;

    return get_uint6( $self->{data}, 102 );
}

sub consent_language {
    my $self = shift;

    return get_char6_sequence( $self->{data}, 108, 2 );
}

sub vendor_list_version {
    my $self = shift;

    return get_uint12( $self->{data}, 120 );
}

sub policy_version {
    my $self = shift;

    return get_uint6( $self->{data}, 132 );
}

sub is_service_specific {
    my $self = shift;

    return is_set( $self->{data}, 138 );
}

sub use_non_standard_stacks {
    my $self = shift;

    return is_set( $self->{data}, 139 );
}

sub is_special_feature_opt_in {
    my ( $self, $id ) = @_;

    croak "invalid special feature id $id: must be between 1 and 12"
      if $id < 1 || $id > 12;

    return is_set( $self->{data}, 140 + $id - 1 );
}

sub is_purpose_consent_allowed {
    my ( $self, $id ) = @_;

    croak "invalid purpose id $id: must be between 1 and 24"
      if $id < 1 || $id > 24;

    return is_set( $self->{data}, 152 + $id - 1 );
}

sub is_purpose_legitimate_interest_allowed {
    my ( $self, $id ) = @_;

    croak "invalid purpose id $id: must be between 1 and 24"
      if $id < 1 || $id > 24;

    return is_set( $self->{data}, 176 + $id - 1 );
}

sub purpose_one_treatment {
    my $self = shift;

    return is_set( $self->{data}, 200 );
}

sub publisher_country_code {
    my $self = shift;

    return get_char6_sequence( $self->{data}, 201, 2 );
}

sub max_vendor_id_consent {
    my $self = shift;

    return get_uint16( $self->{data}, 213 );
}

sub max_vendor_id_legitimate_interest {
    my $self = shift;

    return $self->{legitimate_interest_max_vendor};
}

sub vendor_consent {
    my ( $self, $id ) = @_;

    return $self->{vendor_consents}->contains($id);
}

sub vendor_legitimate_interest {
    my ( $self, $id ) = @_;

    return $self->{vendor_legitimate_interests}->contains($id);
}

sub _is_vendor_consent_range_encoding {
    my $self = shift;

    return is_set( $self->{data}, 229 );
}

sub _parseRangeSection {
    my ( $self, $vendor_bits_required, $start_bit ) = @_;

    my $range_section = GDPR::IAB::TCFv2::RangeSection->new(
        data                 => $self->{data},
        start_bit            => $start_bit,
        vendor_bits_required => $vendor_bits_required,
    );

    return ( $range_section, $range_section->current_offset );
}

sub _parseBitField {
    my ( $self, $vendor_bits_required, $start_bit ) = @_;

    my $bitfield = GDPR::IAB::TCFv2::BitField->new(
        data                 => $self->{data},
        start_bit            => $start_bit,
        vendor_bits_required => $vendor_bits_required,
    );

    return ( $bitfield, $start_bit + $vendor_bits_required );
}

sub looksLikeIsConsentVersion2 {
    my ($gdpr_consent_string) = @_;

    return rindex( $gdpr_consent_string, CONSENT_STRING_TCF2_PREFIX, 0 ) == 0;
}

1;
__END__

=head1 NAME

GDPR::IAB::TCFv2 - Transparency & Consent String version 2 parser

=head1 VERSION

Version v0.0.4

=head1 SYNOPSIS

The purpose of this package is to parse Transparency & Consent String (TC String) as defined by IAB version 2.

    use strict;
    use warnings;
    use feature 'say';
    use GDPR::IAB::TCFv2;

    my $consent = GDPR::IAB::TCFv2->Parse(
        'CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA.argAC0gAAAAAAAAAAAA'
    );

    say $consent->version;             # 2
    say $consent->created;             # epoch 1228644257
    say $consent->last_updated;        # epoch 1326215413
    say $consent->cmp_id;              # 21
    say $consent->cmp_version;         # 7
    say $consent->consent_screen;      # 2
    say $consent->consent_language;    # "EN"
    say $consent->vendor_list_version; # 23

    use List::Util qw(all);

    say "consent ok for purpose ids 1, 3, 9 and 10" if all {
        $consent->is_purpose_consent_allowed($_)
    } (1, 3, 9, 10);

    say "weborama (vendor id 284) has consent" if $consent->vendor_consent(284);

=head1 ACRONYMS

GDPR: General Data Protection Regulation L<https://iabeurope.eu/about-us/>
IAB: Interactive Advertising Bureau L<About IAB|https://iabeurope.eu/about-us/>
TCF: The Transparency & Consent Framework L<TCF v2.2|https://iabeurope.eu/transparency-consent-framework/>

=head1 CONSTRUCTOR

=head2 Parse

The Parse method will decode and validate a base64 encoded version of the tcf v2 string.

Will die if can't decode the string.

    use GDPR::IAB::TCFv2;

    my $consent = GDPR::IAB::TCFv2->Parse(
        'CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA.argAC0gAAAAAAAAAAAA'
    );

=head1 METHODS

=head2 version


Version number of the encoding format. The value is 2 for this format.

=head2 created

Epoch time format when TC String was created in numeric format. You can easily parse with L<DateTime> if needed.

=head2 last_updated

Epoch time format when TC String was last updated in numeric format. You can easily parse with L<DateTime> if needed.

=head2 cmp_id

Consent Management Platform ID that last updated the TC String. Is a unique ID will be assigned to each Consent Management Platform.

=head2 cmp_version

Consent Management Platform version of the CMP that last updated this TC String.
Each change to a CMP should increment their internally assigned version number as a record of which version the user gave consent and transparency was established.

=head2 consent_screen

CMP Screen number at which consent was given for a user with the CMP that last updated this TC String.
The number is a CMP internal designation and is CmpVersion specific. The number is used for identifying on which screen a user gave consent as a record.

=head2 consent_language

Two-letter L<ISO 639-1|https://en.wikipedia.org/wiki/ISO_639-1> language code in which the CMP UI was presented.

=head2 vendor_list_version

Number corresponds to L<GVL|https://github.com/InteractiveAdvertisingBureau/GDPR-Transparency-and-Consent-Framework/blob/master/TCFv2/IAB%20Tech%20Lab%20-%20Consent%20string%20and%20vendor%20list%20formats%20v2.md#the-global-vendor-list> vendorListVersion.
Version of the GVL used to create this TC String.

=head2 is_purpose_consent_allowed

The user's consent value for each Purpose established on the legal basis of consent.

    my $ok = $instance->is_purpose_consent_allowed(1);

=head2 is_purpose_legitimate_interest_allowed

The user's consent value for each Purpose established on the legal basis of legitimate interest.

    my $ok = $instance->is_purpose_legitimate_interest_allowed(1);

=head2 purpose_one_treatment

CMPs can use the PublisherCC field to indicate the legal jurisdiction the publisher is under to help vendors determine whether the vendor needs consent for Purpose 1.

Returns true if Purpose 1 was NOT disclosed at all.

Returns false if Purpose 1 was disclosed commonly as consent as expected by the L<Policies|https://iabeurope.eu/iab-europe-transparency-consent-framework-policies/>.

=head2 publisher_country_code

Two-letter L<ISO 639-1|https://en.wikipedia.org/wiki/ISO_639-1> language code of the country that determines legislation of reference. 
Commonly, this corresponds to the country in which the publisher's business entity is established.

=head2 max_vendor_id_consent

The maximum Vendor ID that is represented in the following bit field or range encoding.

Because this section can be a variable length, this indicates the last ID of the section so that a decoder will know when it has reached the end.

=head2 vendor_consent

The consent value for each Vendor ID 

=head2 max_vendor_id_legitimate_interest

The maximum Vendor ID that is represented in the following bit field or range encoding.

Because this section can be a variable length, this indicates the last ID of the section so that a decoder will know when it has reached the end.

=head2 vendor_legitimate_interest
	
The legitimate interest value for each Vendor ID

=head1 FUNCTIONS

=head2 looksLikeIsConsentVersion2

Will check if a given tc string starts with a literal "C".

=head1 SEE ALSO

You can find the original documentation of the TCF v2 from IAB documentation L<here|https://github.com/InteractiveAdvertisingBureau/GDPR-Transparency-and-Consent-Framework/blob/master/TCFv2/IAB%20Tech%20Lab%20-%20Consent%20string%20and%20vendor%20list%20formats%20v2.md>.

=head1 AUTHOR

Tiago Peczenyj (tiago dot peczentj at gmail dot com)

=head1 BUGS

Please report any bugs or feature requests to L<https://github.com/peczenyj/GDPR-IAB-TCFv2/issues>.

=head1 LICENSE AND COPYRIGHT

Copyright 2023 Tiago Peczenyj

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See L<http://dev.perl.org/licenses/> for more information.

=head1 DISCLAIMER

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=cut
