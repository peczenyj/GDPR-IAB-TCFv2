use strict;
use warnings;
use Test::More;

eval "use Test::PerlTidy";
plan skip_all => "Test::PerlTidy required for tidying" if $@;

run_tests(
    path       => '.',
    perltidyrc => '.perltidyrc',
    exclude    => [ qr{blib/}, qr{GDPR-IAB-TCFv2-.*}, qr{\.bak$}, qr{\.old$} ],
);
