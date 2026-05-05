use strict;
use warnings;
use Test::More;
use JSON::PP;
use File::Spec;

my $bin = File::Spec->catfile( 'bin', 'iabtcfv2' );
my $tc_string =
  'CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA';

# Use $^X to ensure we use the same perl interpreter
my $perl = $^X;

# Test basic dump (JSON Line)
my $output = `$perl -Ilib $bin dump $tc_string`;
ok( $output, "Got output from CLI dump" );

my $json = eval { decode_json($output) };
ok( $json, "Output is valid JSON" );
is( $json->{version}, 2, "Parsed version is correct" );

# Test pretty print
my $pretty_output = `$perl -Ilib $bin dump --pretty $tc_string`;
like(
    $pretty_output,
    qr/"version"\s*:\s*2/,
    "Pretty output contains version"
);
like( $pretty_output, qr/\n    "/, "Pretty output contains indentation" );

# Test array output
my $array_output = `$perl -Ilib $bin dump --array $tc_string $tc_string`;
my $array_json   = eval { decode_json($array_output) };
ok( $array_json, "Output is valid JSON array" );
is( ref($array_json),     'ARRAY', "Root is an array" );
is( scalar(@$array_json), 2,       "Array contains two elements" );

# Test STDIN (using Perl to avoid shell-specific echo issues)
my $stdin_output = `\"$perl\" -Ilib $bin dump <<EOF
$tc_string
EOF
`;

# Fallback for Windows if heredoc fails in backticks
if ( !$stdin_output ) {
    $stdin_output = `$perl -e "print '$tc_string'" | $perl -Ilib $bin dump`;
}

my $stdin_json = eval { decode_json($stdin_output) };
ok( $stdin_json, "Parsed from STDIN correctly" )
  or diag("Output was: $stdin_output");
is( $stdin_json->{version}, 2, "Parsed version from STDIN is correct" );

done_testing();
