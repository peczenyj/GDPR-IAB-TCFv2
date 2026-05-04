#!/usr/bin/env perl

use strict;
use warnings;

use Benchmark qw(:all);
use lib 'lib';
use GDPR::IAB::TCFv2;
use GDPR::IAB::TCFv2::Validator;
use GDPR::IAB::TCFv2::CMPValidator;
use File::Spec;

my $corpus_file = 't/corpus/gdpr_subset.txt';
my $cmp_file    = 't/corpus/cmp-list.json';

# Load corpus into memory
open my $fh, '<', $corpus_file or die "Missing corpus: $!";
my @strings = <$fh>;
chomp @strings;
close $fh;

# Setup CMP Validator
my $cmp_v =
  GDPR::IAB::TCFv2::CMPValidator->new( file => $cmp_file, now => 1776254400 );

# Setup Validators
my $v_simple = GDPR::IAB::TCFv2::Validator->new(
    vendor_id           => 284,
    consent_purpose_ids => [ 1, 3 ],
);

my $v_cmp = GDPR::IAB::TCFv2::Validator->new(
    vendor_id           => 284,
    consent_purpose_ids => [ 1, 3 ],
    cmp_validator       => $cmp_v,
);

print "Benchmarking with " . scalar(@strings) . " real-world TC strings...\n";

my $idx = 0;
cmpthese(
    -5,
    {   '01_Parse' => sub {
            my $tc = GDPR::IAB::TCFv2->Parse( $strings[ $idx++ % @strings ] );
        },
        '02_Validate_Simple' => sub {
            $v_simple->validate( $strings[ $idx++ % @strings ] );
        },
        '03_Validate_With_CMP' => sub {
            $v_cmp->validate( $strings[ $idx++ % @strings ] );
        },
    }
);

print "\nIndividual Performance Estimation (Direct):\n";
my $count = 50000;
my $t1    = timeit(
    $count,
    sub { GDPR::IAB::TCFv2->Parse( $strings[ $idx++ % @strings ] ) }
);
printf "Raw Parse Speed: %.2f strings/sec\n",
  $count / ( $t1->[0] + $t1->[1] || 1 );

my $t2 =
  timeit( $count, sub { $v_cmp->validate( $strings[ $idx++ % @strings ] ) } );
printf "Full Validation Speed (with CMP): %.2f checks/sec\n",
  $count / ( $t2->[0] + $t2->[1] || 1 );

