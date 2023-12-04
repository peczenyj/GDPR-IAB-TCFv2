# NAME

GDPR::IAB::TCFv2 - Transparency & Consent String version 2 parser

# VERSION

Version v0.0.4

# SYNOPSIS

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

# ACRONYMS

GDPR: General Data Protection Regulation [https://iabeurope.eu/about-us/](https://iabeurope.eu/about-us/)
IAB: Interactive Advertising Bureau [About IAB](https://iabeurope.eu/about-us/)
TCF: The Transparency & Consent Framework [TCF v2.2](https://iabeurope.eu/transparency-consent-framework/)

# CONSTRUCTOR

## Parse

The Parse method will decode and validate a base64 encoded version of the tcf v2 string.

Will die if can't decode the string.

    use GDPR::IAB::TCFv2;

    my $consent = GDPR::IAB::TCFv2->Parse(
        'CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA.argAC0gAAAAAAAAAAAA'
    );

# METHODS

## version

Version number of the encoding format. The value is 2 for this format.

## created

Epoch time format when TC String was created in numeric format. You can easily parse with [DateTime](https://metacpan.org/pod/DateTime) if needed.

## last\_updated

Epoch time format when TC String was last updated in numeric format. You can easily parse with [DateTime](https://metacpan.org/pod/DateTime) if needed.

## cmp\_id

Consent Management Platform ID that last updated the TC String. Is a unique ID will be assigned to each Consent Management Platform.

## cmp\_version

Consent Management Platform version of the CMP that last updated this TC String.
Each change to a CMP should increment their internally assigned version number as a record of which version the user gave consent and transparency was established.

## consent\_screen

CMP Screen number at which consent was given for a user with the CMP that last updated this TC String.
The number is a CMP internal designation and is CmpVersion specific. The number is used for identifying on which screen a user gave consent as a record.

## consent\_language

Two-letter [ISO 639-1](https://en.wikipedia.org/wiki/ISO_639-1) language code in which the CMP UI was presented.

## vendor\_list\_version

Number corresponds to [GVL](https://github.com/InteractiveAdvertisingBureau/GDPR-Transparency-and-Consent-Framework/blob/master/TCFv2/IAB%20Tech%20Lab%20-%20Consent%20string%20and%20vendor%20list%20formats%20v2.md#the-global-vendor-list) vendorListVersion.
Version of the GVL used to create this TC String.

## is\_purpose\_consent\_allowed

The user's consent value for each Purpose established on the legal basis of consent.

    my $ok = $instance->is_purpose_consent_allowed(1);

## is\_purpose\_legitimate\_interest\_allowed

The user's consent value for each Purpose established on the legal basis of legitimate interest.

    my $ok = $instance->is_purpose_legitimate_interest_allowed(1);

## purpose\_one\_treatment

CMPs can use the PublisherCC field to indicate the legal jurisdiction the publisher is under to help vendors determine whether the vendor needs consent for Purpose 1.

Returns true if Purpose 1 was NOT disclosed at all.

Returns false if Purpose 1 was disclosed commonly as consent as expected by the [Policies](https://iabeurope.eu/iab-europe-transparency-consent-framework-policies/).

## publisher\_country\_code

Two-letter [ISO 639-1](https://en.wikipedia.org/wiki/ISO_639-1) language code of the country that determines legislation of reference. 
Commonly, this corresponds to the country in which the publisher's business entity is established.

## max\_vendor\_id\_consent

The maximum Vendor ID that is represented in the following bit field or range encoding.

Because this section can be a variable length, this indicates the last ID of the section so that a decoder will know when it has reached the end.

## vendor\_consent

The consent value for each Vendor ID 

## max\_vendor\_id\_legitimate\_interest

The maximum Vendor ID that is represented in the following bit field or range encoding.

Because this section can be a variable length, this indicates the last ID of the section so that a decoder will know when it has reached the end.

## vendor\_legitimate\_interest

The legitimate interest value for each Vendor ID

# FUNCTIONS

## looksLikeIsConsentVersion2

Will check if a given tc string starts with a literal "C".

# SEE ALSO

You can find the original documentation of the TCF v2 from IAB documentation [here](https://github.com/InteractiveAdvertisingBureau/GDPR-Transparency-and-Consent-Framework/blob/master/TCFv2/IAB%20Tech%20Lab%20-%20Consent%20string%20and%20vendor%20list%20formats%20v2.md).

# AUTHOR

Tiago Peczenyj (tiago dot peczentj at gmail dot com)

# BUGS

Please report any bugs or feature requests to [https://github.com/peczenyj/GDPR-IAB-TCFv2/issues](https://github.com/peczenyj/GDPR-IAB-TCFv2/issues).

# LICENSE AND COPYRIGHT

Copyright 2023 Tiago Peczenyj

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See [http://dev.perl.org/licenses/](http://dev.perl.org/licenses/) for more information.

# DISCLAIMER

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
