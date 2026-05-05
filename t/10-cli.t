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

my $stdin_json   = eval { decode_json($stdin_output) };
ok( $stdin_json, "Parsed from STDIN correctly" )
  or diag("Output was: $stdin_output");
is( $stdin_json->{version}, 2, "Parsed version from STDIN is correct" );

# Test Error Handling
my $invalid_str = "INVALID_STRING_XYZ";

# 1. Default Error JSON
my $err_output = `$perl -Ilib $bin dump $invalid_str 2>/dev/null`;
my $err_json   = eval { decode_json($err_output) };
ok( $err_json, "Invalid string produces JSON error object" );
is( $err_json->{success}, JSON::PP::false, "Error object success is false" );
is( $err_json->{tc_string}, $invalid_str, "Error object includes raw string" );

# 2. --ignore-errors
my $ignore_output = `$perl -Ilib $bin dump --ignore-errors $invalid_str 2>/dev/null`;
is( $ignore_output, "", "--ignore-errors produces no output for bad string" );

# 3. --fail-fast
my $ff_output = `$perl -Ilib $bin dump --fail-fast $invalid_str 2>/dev/null`;
ok( $? != 0, "--fail-fast exits with non-zero code" );

# 4. --errors-to-stderr
# Use a temporary file to capture stderr safely
my $stderr_file = File::Spec->catfile( File::Spec->tmpdir(), "tcf_stderr_$$" );
my $e2s_stdout =
  `$perl -Ilib $bin dump --quiet --errors-to-stderr $invalid_str 2>$stderr_file`;

is( $e2s_stdout, "", "--errors-to-stderr stdout is empty for bad string" );

my $e2s_stderr = "";
if ( -f $stderr_file ) {
    open my $fh, '<', $stderr_file;
    $e2s_stderr = join '', <$fh>;
    close $fh;
    unlink $stderr_file;
}

my $e2s_stderr_json = eval { decode_json($e2s_stderr) };
ok( $e2s_stderr_json, "--errors-to-stderr routes JSON to stderr" )
  or diag("Stderr was: $e2s_stderr");

done_testing();

