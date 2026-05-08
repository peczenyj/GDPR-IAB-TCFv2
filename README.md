<div>
    <a href="https://cpants.cpanauthors.org/dist/GDPR-IAB-TCFv2"><img src="https://cpants.cpanauthors.org/dist/GDPR-IAB-TCFv2.svg" alt='Kwalitee'/></a>
</div>

<div>
    <a href="https://github.com/peczenyj/GDPR-IAB-TCFv2/actions/workflows/linux.yml"><img src="https://github.com/peczenyj/GDPR-IAB-TCFv2/actions/workflows/linux.yml/badge.svg" alt='tests'/></a>
</div>

<div>
    <a href="https://github.com/peczenyj/GDPR-IAB-TCFv2/actions/workflows/windows.yml"><img src="https://github.com/peczenyj/GDPR-IAB-TCFv2/actions/workflows/windows.yml/badge.svg" alt='tests'/></a>
</div>

<div>
    <a href="https://github.com/peczenyj/GDPR-IAB-TCFv2/actions/workflows/macos.yml"><img src="https://github.com/peczenyj/GDPR-IAB-TCFv2/actions/workflows/macos.yml/badge.svg" alt='tests'/></a>
</div>

<div>
    <a href="https://coveralls.io/github/peczenyj/GDPR-IAB-TCFv2?branch=main"><img src="https://coveralls.io/repos/github/peczenyj/GDPR-IAB-TCFv2/badge.svg?branch=main" alt='Coverage Status' /></a>
</div>

<div>
    <a href="https://github.com/peczenyj/GDPR-IAB-TCFv2/blob/master/LICENSE"><img src="https://img.shields.io/cpan/l/GDPR-IAB-TCFv2.svg" alt='license'/></a>
</div>

<div>
    <a href="https://metacpan.org/dist/GDPR-IAB-TCFv2"><img src="https://img.shields.io/cpan/v/GDPR-IAB-TCFv2.svg" alt='cpan'/></a>
</div>

# NAME

GDPR::IAB::TCFv2 - TCF v2.3 (Transparency & Consent String) parser

# PROJECT STATUS

`GDPR::IAB::TCFv2` entered **maintenance mode** on 2026-05-08 with the
v0.400 release. The core parser, validator, and CMP-validator surfaces
are considered feature-complete for the IAB TCF v2.3 specification.

In maintenance mode the maintainer commits to bug fixes, security
fixes, CPAN-tester regression triage, and tracking IAB-spec updates
(TCF v2.4 / v3 if and when they ship). Larger feature work -- the
remaining roadmap phases (GVL-aware validator, Special Features /
Special Purposes, CLI configuration loading), the distribution items
(DockerHub automation, Debian package), and the sister-distribution
ideas in ["ECOSYSTEM"](#ecosystem) -- is now tracked as `help-wanted` issues on
GitHub.

Patches and PRs from the community are welcome and will continue to be
reviewed. See `TODO.pod` at the repository root for the full
help-wanted list and `CONTRIBUTING.pod` for the patching workflow.

# SYNOPSIS

The purpose of this package is to parse Transparency & Consent String (TC String) as defined by IAB version 2.

    use strict;
    use warnings;
    
    use GDPR::IAB::TCFv2;
    use GDPR::IAB::TCFv2::Constants::Purpose qw<:all>;
    use GDPR::IAB::TCFv2::Constants::SpecialFeature qw<:all>;
    use GDPR::IAB::TCFv2::Constants::RestrictionType qw<:all>;

    my $consent = GDPR::IAB::TCFv2->Parse(
        'CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA.argAC0gAAAAAAAAAAAA'
    );

    use feature qw<say>;

    say $consent->version;             # 2
    say $consent->created;             # epoch 1228644257 or 07/12/2008
    say $consent->last_updated;        # epoch 1326215413 or 10/01/2012
    say $consent->cmp_id;              # 21 - Traffective GmbH 
    say $consent->cmp_version;         # 7
    say $consent->consent_screen;      # 2
    say $consent->consent_language;    # "EN"
    say $consent->vendor_list_version; # 23

    use List::MoreUtils qw<all>;

    say "find consent for purpose ids 1, 3, 9 and 10" if all {
        $consent->is_purpose_consent_allowed($_)
    } ( # constants exported by GDPR::IAB::TCFv2::Constants::Purpose
        InfoStorageAccess,       #  1
        PersonalizationProfile,  #  3
        MarketResearch,          #  9
        DevelopImprove,          # 10
    );

    say "find consent for vendor id 284 (Weborama)" if $consent->vendor_consent(284);

    # Geolocation exported by GDPR::IAB::TCFv2::Constants::SpecialFeature
    say "user is opt in for special feature 'Geolocation (id 1)'" 
        if $consent->is_special_feature_opt_in(Geolocation);

    # NotAllowed exported by GDPR::IAB::TCFv2::Constants::RestrictionType
    say "publisher restriction for purpose Info Storage Access (1), restriction type NotAllowed (0) for weborama (284)"
        if $consent->check_publisher_restriction(InfoStorageAccess, NotAllowed, 284);

For policy-driven checks against an entire vendor profile (required purposes,
legal basis, GVL flexibility, optional Disclosed Vendors enforcement),
use the [GDPR::IAB::TCFv2::Validator](https://metacpan.org/pod/GDPR%3A%3AIAB%3A%3ATCFv2%3A%3AValidator) companion class instead of stringing
the predicates above together by hand:

    use GDPR::IAB::TCFv2::Validator;

    my $validator = GDPR::IAB::TCFv2::Validator->new(
        vendor_id                       => 284,
        consent_purpose_ids             => [ 1, 3 ],
        legitimate_interest_purpose_ids => [ 7 ],
    );

    my $result = $validator->validate($consent);   # fail-fast
    # ...or $validator->validate_all($consent) to accumulate every reason

    if ($result) {
        # vendor 284 has every required permission
    }
    else {
        warn "compliance failed: $result\n";   # stringifies to the reasons
        log_failure($_) for $result->reasons;
    }

# COMMAND LINE TOOLS

This distribution includes a unified command line tool to work with TC strings.

## iabtcfv2

The `iabtcfv2` utility provides several subcommands for TCF v2.3 strings.

### dump

Parses TC strings and output them as JSON.

    # Basic usage
    iabtcfv2 dump "CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA"

    # Pretty printed JSON
    iabtcfv2 dump --pretty "CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA"

    # Stream multiple strings from STDIN as JSON Lines
    cat strings.txt | iabtcfv2 dump

    # Pipe through `jq -s` if you need a single JSON array
    cat strings.txt | iabtcfv2 dump | jq -s .

    # Short flags can be bundled (the last bundled short may take a value)
    iabtcfv2 dump -pi "CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA"
    iabtcfv2 dump -pv 284 "CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA"

    # Long options accept the GNU `--opt=value` form
    iabtcfv2 dump --vendor-id=284 "CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA"

### validate

Validates TC strings against a vendor identity and a set of declared purpose
lists, emitting one JSON record per string (or text lines with `--text`).
The vendor must be allowed for every purpose in `--consent-purposes` on a
consent basis, and for every purpose in `--legitimate-interest-purposes`
on a legitimate-interest basis. Exit code is `0` when every string is
valid, `1` on any parse or validation failure, `2` on bad CLI usage.

    # Basic usage: vendor must appear in the TC string
    iabtcfv2 validate -v 284 "CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA"

    # Require vendor 284 to be allowed for purposes 1 and 3 on consent basis
    iabtcfv2 validate -v 284 -C 1,3 "CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA"

    # Require both consent (purposes 1, 3) and legitimate interest (purpose 7)
    iabtcfv2 validate -v 284 -C 1,3 -L 7 "CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA"

    # Accumulate every failing rule (validate_all) instead of fail-fast
    iabtcfv2 validate -av 284 -C 1,3 -L 7 "CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA"

    # Human-readable text output instead of JSON
    iabtcfv2 validate -tv 284 -C 1,3 "CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA"

    # Reject TC strings whose policy version is below 5 (TCF v2.3)
    iabtcfv2 validate -v 284 -m 5 "CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA"

    # Pipeline-friendly: -q suppresses output, only the exit code is meaningful
    if iabtcfv2 validate -qv 284 -C 1,3 "$tc_string"; then
        echo "ok"
    fi

    # Stream multiple strings from STDIN as JSON Lines (pipe through
    # `jq -s` if you need a single JSON array)
    cat strings.txt | iabtcfv2 validate -v 284 -C 1,3

See `iabtcfv2 --help` or `perldoc iabtcfv2` for more details.

# DOCKER USAGE

This tool is also available as a Docker image on Docker Hub.

## Basic Usage

    docker run --rm peczenyj/gdpr-iab-tcfv2 dump "CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA"

## Processing Streams (STDIN)

To process a stream of strings via pipe:

    cat strings.txt | docker run -i --rm peczenyj/gdpr-iab-tcfv2 dump

To type strings manually:

    docker run -it --rm peczenyj/gdpr-iab-tcfv2 dump

# ACRONYMS

[GDPR](https://gdpr-info.eu/): General Data Protection Regulation

[IAB](https://iabeurope.eu/about-us/): Interactive Advertising Bureau 

[TCF](https://iabeurope.eu/transparency-consent-framework/): The Transparency & Consent Framework

# CONSTRUCTOR

## Parse

The Parse method will decode and validate a base64 encoded version of the tcf v2 string.

Will return a `GDPR::IAB::TCFv2` immutable object that allow easy access to different properties.

Will die if can't decode the string.

    use GDPR::IAB::TCFv2;

    my $consent = GDPR::IAB::TCFv2->Parse(
        'CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA.argAC0gAAAAAAAAAAAA'
    );

or

    use GDPR::IAB::TCFv2;

    my $consent = GDPR::IAB::TCFv2->Parse(
        'CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA.argAC0gAAAAAAAAAAAA',
        json => {
            verbose        => 0,
            compact        => 1,
            use_epoch      => 0,
            boolean_values => [ 0, 1 ],
            date_format    => '%Y%m%d',    # yyymmdd
        },
        strict => 1,
        prefetch => 284,
    );

Parse may receive an optional hash with the following parameters:

- On `strict` mode we will validate if the version of the consent string is the version 2 (or die with an exception).

    Additionally, for TCF v2.3 strings (Policy Version 5+), `strict` mode will enforce that the **Disclosed Vendors** segment is present.

    The `strict` mode is disabled by default.

- The `prefetch` option receives one (as scalar) or more (as arrayref) vendor ids. 

    This is useful when parsing a range based consent string, since we need to visit all ranges to find a particular id.

- `json` is hashref with the following properties used to customize the json format:
    - `verbose` changes the json encoding. By default we omit some false values such as `vendor_consents` to create 
    a compact json representation. With `verbose` we will present everything. See ["TO\_JSON"](#to_json) for more details.
    - `compact` changes the json encoding. All fields that are a mapping of something to a boolean will be changed to an array
    of all elements keys where the value is true. This affects the following fields:  `special_features_opt_in`,
    `purpose/consents`, `purpose/legitimate_interests`, `vendor/consents` and `vendor/legitimate_interests`. See ["TO\_JSON"](#to_json) for more details.
    - `use_epoch` changes the json encode. By default we format the `created` and `last_updated` are converted to string using 
    [ISO\_8601](https://en.wikipedia.org/wiki/ISO_8601). With `use_epoch` we will return the unix epoch in seconds.
    See ["TO\_JSON"](#to_json) for more details.
    - `boolean_values` if present, expects an arrayref if two elements: the `false` and the `true` values to be used in json encoding.
    If omit, we will try to use `JSON::false` and `JSON::true` if the package [JSON](https://metacpan.org/pod/JSON) is available, else we will fallback to `0` and `1`.
    - `date_format` if present accepts two kinds of value: an `string` (to be used on `POSIX::strftime`) or a code reference to a subroutine that
    will be called with two arguments: epoch in seconds and nanoseconds. If omitted the format [ISO\_8601](https://en.wikipedia.org/wiki/ISO_8601) will be used
    except if the option `use_epoch` is true.
    - `vendor_id` if present, filters the JSON output to only include data for the specific vendor ID. This affects the `vendor` and `publisher/restrictions` sections, drastically reducing the size of the output.

# METHODS

## tc\_string

Returns the original consent string.

The consent object [GDPR::IAB::TCFv2](https://metacpan.org/pod/GDPR%3A%3AIAB%3A%3ATCFv2) will call this method on string interpolations.

## version

Version number of the encoding format. The value is 2 for this format.

## created

Epoch time format when TC String was created in numeric format. You can easily parse with [DateTime](https://metacpan.org/pod/DateTime) if needed.

On scalar context it returns epoch in seconds. On list context it returns epoch in seconds and nanoseconds.

    use GDPR::IAB::TCFv2;
    use Test::More tests => 3;

    my $consent = GDPR::IAB::TCFv2->Parse(
        'CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA.argAC0gAAAAAAAAAAAA'
    );

    is $consent->created, 1228644257,
      'should return the creation epoch 07/12/2008';

    my ( $seconds, $nanoseconds ) = $consent->created;
    is $seconds, 1228644257,
        'should return the creation epoch 07/12/2008 on list context';
    is $nanoseconds, 700000000,
        'should return the 700000000 nanoseconds of epoch on list context';
    

## last\_updated

Epoch time format when TC String was last updated in numeric format. You can easily parse with [DateTime](https://metacpan.org/pod/DateTime) if needed.

On scalar context it returns epoch in seconds. On list context it returns epoch in seconds and nanoseconds, like the `created`

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

## policy\_version

Version of policy used within [GVL](https://github.com/InteractiveAdvertisingBureau/GDPR-Transparency-and-Consent-Framework/blob/master/TCFv2/IAB%20Tech%20Lab%20-%20Consent%20string%20and%20vendor%20list%20formats%20v2.md#the-global-vendor-list).

From the corresponding field in the GVL that was used for obtaining consent.

## is\_v22\_plus

Returns true if the TC string uses Policy Version 4 or higher (TCF v2.2+).

## is\_v23

Returns true if the TC string uses Policy Version 5 or higher (TCF v2.3).

## is\_service\_specific

This field must always have the value of 1. When a Vendor encounters a TC String with `is_service_specific=0` then it is considered invalid.

## use\_non\_standard\_stacks

If true, CMP used non-IAB standard texts during consent gathering.

Setting this to 1 signals to Vendors that a private CMP has modified standard Stack descriptions and/or their translations and/or that a CMP has modified or supplemented standard Illustrations and/or their translations as allowed by the policy..

## is\_special\_feature\_opt\_in

If true means Opt in.

The TCF [Policies](https://iabeurope.eu/iab-europe-transparency-consent-framework-policies/) designates certain Features as "special" which means a CMP must afford the user a means to opt in to their use. These "Special Features" are published and numerically identified in the [Global Vendor List separately](https://github.com/InteractiveAdvertisingBureau/GDPR-Transparency-and-Consent-Framework/blob/master/TCFv2/IAB%20Tech%20Lab%20-%20Consent%20string%20and%20vendor%20list%20formats%20v2.md#the-global-vendor-list) from normal Features.

See also: [GDPR::IAB::TCFv2::Constants::SpecialFeature](https://metacpan.org/pod/GDPR%3A%3AIAB%3A%3ATCFv2%3A%3AConstants%3A%3ASpecialFeature).

## is\_purpose\_consent\_allowed

If true means Consent.

The user's consent value for each Purpose established on the legal basis of consent.
Accepts one or more Purpose IDs. Returns true if all Purposes have consent.

    my $ok = $instance->is_purpose_consent_allowed(1);
    my $all_ok = $instance->is_purpose_consent_allowed(1, 2, 3);

Throws an exception if no arguments are provided or if an ID is invalid.

See also: [GDPR::IAB::TCFv2::Constants::Purpose](https://metacpan.org/pod/GDPR%3A%3AIAB%3A%3ATCFv2%3A%3AConstants%3A%3APurpose).

## is\_purpose\_legitimate\_interest\_allowed

The user's consent value for each Purpose established on the legal basis of legitimate interest.
Accepts one or more Purpose IDs. Returns true if all Purposes have legitimate interest.

    my $ok = $instance->is_purpose_legitimate_interest_allowed(1);
    my $all_ok = $instance->is_purpose_legitimate_interest_allowed(1, 2, 3);

Throws an exception if no arguments are provided or if an ID is invalid.

See also: [GDPR::IAB::TCFv2::Constants::Purpose](https://metacpan.org/pod/GDPR%3A%3AIAB%3A%3ATCFv2%3A%3AConstants%3A%3APurpose).

## purpose\_one\_treatment

CMPs can use the `publisher_country_code` field to indicate the legal jurisdiction the publisher is under to help vendors determine whether the vendor needs consent for Purpose 1.

Returns true if Purpose 1 was NOT disclosed at all.

Returns false if Purpose 1 was disclosed commonly as consent as expected by the [Policies](https://iabeurope.eu/iab-europe-transparency-consent-framework-policies/).

## publisher\_country\_code

Two-letter [ISO 639-1](https://en.wikipedia.org/wiki/ISO_639-1) language code of the country that determines legislation of reference. 
Commonly, this corresponds to the country in which the publisher's business entity is established.

## max\_vendor\_id\_consent

The maximum Vendor ID that is represented in the following bit field or range encoding.

Because this section can be a variable length, this indicates the last ID of the section so that a decoder will know when it has reached the end.

## vendor\_consent

If true, vendor has consent.

The consent value for each Vendor ID.

    my $ok = $instance->vendor_consent(284); # if true, consent ok for Weborama (vendor id 284).

## max\_vendor\_id\_legitimate\_interest

The maximum Vendor ID that is represented in the following bit field or range encoding.

Because this section can be a variable length, this indicates the last ID of the section so that a decoder will know when it has reached the end.

## vendor\_legitimate\_interest

If true, legitimate interest established.

The legitimate interest value for each Vendor ID

    my $ok = $instance->vendor_legitimate_interest(284); # if true, legitimate interest established for Weborama (vendor id 284).

## disclosed\_vendor

If true, the vendor was disclosed to the user (Segment 1 or 5).

    say "Vendor 284 was disclosed" if $consent->disclosed_vendor(284);

## has\_vendor\_disclosure

Returns true (1) if the TC string contains a "Disclosed Vendors" segment (ID 1 or 5), and false (0) otherwise.

## allowed\_vendor

If true, the vendor is in the "Allowed Vendors" segment (Segment 2). This is typically used for service-specific TC strings.

    say "Vendor 284 is allowed" if $consent->allowed_vendor(284);

## is\_vendor\_consent\_allowed

Check if a vendor has consent for a list of purposes, respecting publisher restrictions.

    if ($consent->is_vendor_consent_allowed(284, 1, 2, 3)) {
        # ...
    }

## is\_vendor\_legitimate\_interest\_allowed

Check if a vendor has legitimate interest for a list of purposes, respecting publisher restrictions.

    if ($consent->is_vendor_legitimate_interest_allowed(284, 2, 4)) {
        # ...
    }

## is\_vendor\_allowed\_for\_any\_basis

Check if a vendor has either consent or legitimate interest for a list of purposes, respecting publisher restrictions.

    if ($consent->is_vendor_allowed_for_any_basis(284, 1, 2)) {
        # ...
    }

## has\_publisher\_restrictions

Returns true (1) if the TC string contains a "Publisher Restrictions" section, and false (0) otherwise.

## check\_publisher\_restriction

It true, there is a publisher restriction of certain type, for a given purpose id, for a given vendor id:

    # return true if there is publisher restriction to vendor 284 regarding purpose id 1 
    # with restriction type 0 'Purpose Flatly Not Allowed by Publisher'
    my $ok = $instance->check_publisher_restriction(1, 0, 284);

or

    my $ok = $instance->check_publisher_restriction(
        purpose_id       => 1, 
        restriction_type => 0,  
        vendor_id        => 284);

Version 2.0 of the Framework introduced the ability for publishers to signal restrictions on how vendors may process personal data. Restrictions can be of two types:

- Purposes. Restrict the purposes for which personal data is processed by a vendor.
- Legal basis. Specify the legal basis upon which a publisher requires a vendor to operate where a vendor has signaled flexibility on legal basis in the GVL.

Publisher restrictions are custom requirements specified by a publisher. In order for vendors to determine if processing is permissible at all for a specific purpose or which legal basis is applicable (in case they signaled flexibility in the GVL) restrictions must be respected.

1. Vendors must always respect a restriction signal that disallows them the processing for a specific purpose regardless of whether or not they have declared that purpose to be "flexible".
2. Vendors that declared a purpose with a default legal basis (consent or legitimate interest respectively) but also declared this purpose as flexible must respect a legal basis restriction if present. That means for example in case they declared a purpose as legitimate interest but also declared that purpose as flexible and there is a legal basis restriction to require consent, they must then check for the consent signal and must not apply the legitimate interest signal.

For the avoidance of doubt:

In case a vendor has declared flexibility for a purpose and there is no legal basis restriction signal it must always apply the default legal basis under which the purpose was registered aside from being registered as flexible. That means if a vendor declared a purpose as legitimate interest and also declared that purpose as flexible it may not apply a "consent" signal without a legal basis restriction signal to require consent.

## is\_vendor\_allowed\_for\_flexible\_purpose

Check if a vendor is allowed for a flexible purpose, given a default legal basis (true if Legitimate Interest, false if Consent).

    if ($consent->is_vendor_allowed_for_flexible_purpose(284, 2, 1)) {
        # vendor 284, purpose 2, default is LI
    }

## publisher\_restrictions

Similar to ["check\_publisher\_restriction"](#check_publisher_restriction) but return an hashref of purpose => { restriction type => bool } for a given vendor.

## publisher\_tc

If the consent string has a `Publisher TC` section, we will decode this section as an instance of [GDPR::IAB::TCFv2::PublisherTC](https://metacpan.org/pod/GDPR%3A%3AIAB%3A%3ATCFv2%3A%3APublisherTC).

Will return undefined if there is no `Publisher TC` section.

## TO\_JSON

Will serialize the consent object into a hash reference. The objective is to be used by [JSON](https://metacpan.org/pod/JSON) package.

With option `convert_blessed`, the encoder will call this method.

    use strict;
    use warnings;
    use feature qw<say>;

    use JSON;
    use DateTime;
    use DateTimeX::TO_JSON formatter => 'DateTime::Format::RFC3339';
    use GDPR::IAB::TCFv2;

    my $consent = GDPR::IAB::TCFv2->Parse(
        'COyiILmOyiILmADACHENAPCAAAAAAAAAAAAAE5QBgALgAqgD8AQACSwEygJyAAAAAA.argAC0gAAAAAAAAAAAA',
        json => {
            compact     => 1,
            date_format => sub { # can be omitted, with DateTimeX::TO_JSON
                my ( $epoch, $ns ) = @_;

                return DateTime->from_epoch( epoch => $epoch )
                ->set_nanosecond($ns);
            },
        },
    );

    my $json    = JSON->new->convert_blessed;
    my $encoded = $json->pretty->encode($consent);

    say $encoded;

Outputs:

    {
        "tc_string" : "COyiILmOyiILmADACHENAPCAAAAAAAAAAAAAE5QBgALgAqgD8AQACSwEygJyAAAAAA",
        "consent_language" : "EN",
        "purpose" : {
            "consents" : [],
            "legitimate_interests" : []
        },
        "cmp_id" : 3,
        "purpose_one_treatment" : false,
        "publisher" : {
            "consents" : [
                2,
                4,
                6,
                8,
                9,
                10
            ],
            "legitimate_interests" : [
                2,
                4,
                5,
                7,
                10
            ],
            "custom_purpose" : {
                "consents" : [],
                "legitimate_interests" : []
            },
            "restrictions" : {}
        },
        "special_features_opt_in" : [],
        "last_updated" : "2020-04-27T20:27:54.200000000Z",
        "use_non_standard_stacks" : false,
        "policy_version" : 2,
        "version" : 2,
        "is_service_specific" : false,
        "created" : "2020-04-27T20:27:54.200000000Z",
        "consent_screen" : 7,
        "vendor_list_version" : 15,
        "cmp_version" : 2,
        "publisher_country_code" : "AA",
        "vendor" : {
            "consents" : [
                23,
                42,
                126,
                127,
                128,
                587,
                613,
                626
            ],
            "legitimate_interests" : []
        }
    }

If [JSON](https://metacpan.org/pod/JSON) is installed, the ["TO\_JSON"](#to_json) method will use `JSON::true` and `JSON::false` as boolean value.

By default it returns a compacted format where we omit the `false` on fields like `vendor_consents` and we convert the dates 
using [ISO\_8601](https://en.wikipedia.org/wiki/ISO_8601). This behaviour can be changed by extra option in the [Parse](https://metacpan.org/pod/Parse) constructor.

# FUNCTIONS

## looksLikeIsConsentVersion2

Will check if a given tc string starts with a literal `C`.

# ECOSYSTEM

The following **sister distributions** are intentionally left as
`help-wanted` ideas rather than shipped from this module. Each one is
companion glue for a popular Perl framework and would add a runtime
dependency on its host framework, so they belong as separate CPAN
distributions rather than features of `GDPR::IAB::TCFv2` itself.

- [GDPR::IAB::TCFv2::Validator::LIVR](https://metacpan.org/pod/GDPR%3A%3AIAB%3A%3ATCFv2%3A%3AValidator%3A%3ALIVR)

    LIVR rule-engine binding for JSON-shaped TC string payloads.

- [GDPR::IAB::TCFv2::Validator::TypeTiny](https://metacpan.org/pod/GDPR%3A%3AIAB%3A%3ATCFv2%3A%3AValidator%3A%3ATypeTiny)

    Reusable Type::Tiny constraints (parameterized by purpose / vendor
    sets) for Moo, Moose, or pure-Perl callers that prefer type-level
    enforcement.

- [Plack::Middleware::GDPR::TCFv2](https://metacpan.org/pod/Plack%3A%3AMiddleware%3A%3AGDPR%3A%3ATCFv2)

    Plack middleware that decodes a TC string from a request header or
    cookie, attaches a parsed `GDPR::IAB::TCFv2` object to `$env`,
    and short-circuits the response when consent is missing or invalid.

- [GDPR::IAB::TCFv2::Validator::Moose](https://metacpan.org/pod/GDPR%3A%3AIAB%3A%3ATCFv2%3A%3AValidator%3A%3AMoose)

    Moose attribute traits and role-based validation for Moose-end-to-end
    projects.

- [GDPR::IAB::TCFv2::Validator::FormValidator](https://metacpan.org/pod/GDPR%3A%3AIAB%3A%3ATCFv2%3A%3AValidator%3A%3AFormValidator)

    `Data::FormValidator` profile glue for legacy applications that drive
    business validation through DFV.

The `help-wanted` issues on GitHub track each of these ideas; see
[https://github.com/peczenyj/GDPR-IAB-TCFv2/issues?q=label%3Aecosystem](https://github.com/peczenyj/GDPR-IAB-TCFv2/issues?q=label%3Aecosystem)
and `TODO.pod` for context.

# SEE ALSO

[GDPR::IAB::TCFv2::Validator](https://metacpan.org/pod/GDPR%3A%3AIAB%3A%3ATCFv2%3A%3AValidator) for declarative compliance checks against a
parsed TC string -- a higher-level API for the per-vendor / per-purpose
permission combinations that this module's predicates expose.

The original documentation of the [TCF v2 from IAB documentation](https://github.com/InteractiveAdvertisingBureau/GDPR-Transparency-and-Consent-Framework/blob/master/TCFv2/IAB%20Tech%20Lab%20-%20Consent%20string%20and%20vendor%20list%20formats%20v2.md).

# AUTHOR

Tiago Peczenyj [mailto:tiago.peczenyj+gdpr-iab-tcfv2@gmail.com](mailto:tiago.peczenyj+gdpr-iab-tcfv2@gmail.com)

# THANKS

Special thanks to [ikegami](https://metacpan.org/author/IKEGAMI) for the patience on several question about Perl on [Stack Overflow](https://stackoverflow.com).

# BUGS

Please report any bugs or feature requests to [https://github.com/peczenyj/GDPR-IAB-TCFv2/issues](https://github.com/peczenyj/GDPR-IAB-TCFv2/issues).

# LICENSE AND COPYRIGHT

Copyright 2023-2026 Tiago Peczenyj

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
