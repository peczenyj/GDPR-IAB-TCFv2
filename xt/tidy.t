use strict;
use warnings;
use Test::More;

eval "use Test::Perl::Tidy";
plan skip_all => "Test::Perl::Tidy required for tidying" if $@;

run_tests(
    path       => '.',
    perltidyrc => '.perltidyrc',
    exclude    => [ qr{blib/}, qr{GDPR-IAB-TCFv2-.*}, qr{\.bak$}, qr{\.old$} ],
);
