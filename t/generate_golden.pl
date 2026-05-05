#!/usr/bin/env perl

use strict;
use warnings;

use lib 'lib';
use GDPR::IAB::TCFv2;
use JSON::PP;
use FindBin;
use File::Spec;

my $corpus_dir  = File::Spec->catdir( $FindBin::Bin, 'corpus' );
my $input_file  = File::Spec->catfile( $corpus_dir, 'gdpr_subset.txt' );
my $output_file = File::Spec->catfile( $corpus_dir, 'golden.jsonl' );

open my $ifh, '<', $input_file  or die "Could not open $input_file: $!";
open my $ofh, '>', $output_file or die "Could not open $output_file: $!";
my $json = JSON::PP->new->canonical->utf8;

while ( my $line = <$ifh> ) {
    chomp $line;
    next unless $line;

    eval {
        my $consent = GDPR::IAB::TCFv2->Parse(
            $line,
            json => { boolean_values => [ JSON::PP::false, JSON::PP::true ] }
        );

        my $data = {
            tc_string      => $line,
            expect_failure => JSON::PP::false,
            tests          => {
                to_json  => $consent->TO_JSON,
                metadata => {
                    version       => $consent->version,
                    cmp_id        => $consent->cmp_id,
                    created_epoch => scalar( $consent->created ),
                },
                sampling => {
                    purpose_1_consent =>
                      $consent->is_purpose_consent_allowed(1)
                    ? JSON::PP::true
                    : JSON::PP::false,
                    vendor_284_consent => $consent->vendor_consent(284)
                    ? JSON::PP::true
                    : JSON::PP::false,
                }
            }
        };

        # Add new methods if they exist (Phase 0+)
        if ( $consent->can('is_vendor_consent_allowed') ) {
            $data->{tests}{sampling}{vendor_284_purpose_1_allowed} =
              $consent->is_vendor_consent_allowed( 284, 1 ) ? \1 : \0;
        }

        print $ofh $json->encode($data) . "\n";
    };
    if ($@) {
        my $err = $@;
        $err =~ s/ at .* line \d+.*//s;   # Strip file/line for better matching
        print $ofh $json->encode(
            {   tc_string      => $line,
                expect_failure => JSON::PP::true,
                error_match    => $err,
            }
        ) . "\n";
    }
}

close $ifh;
close $ofh;

print "Golden file generated at $output_file\n";
