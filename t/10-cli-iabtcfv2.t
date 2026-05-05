use strict;
use warnings;
use Test::More;

eval { require JSON; 1 } or eval { require JSON::PP; 1 }
  or plan skip_all => 'JSON or JSON::PP required for this test';

my $json_pkg = JSON->can('new') ? 'JSON' : 'JSON::PP';
use File::Spec;

my $bin = File::Spec->catfile( 'bin', 'iabtcfv2' );
my $tc_string =
  'CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA';

# Use $^X to ensure we use the same perl interpreter
my $perl    = $^X;
my $devnull = ( $^O eq 'MSWin32' ) ? 'NUL' : '/dev/null';

sub decode_helper {
    my $json_str = shift;
    return eval { $json_pkg->new->utf8->decode($json_str) };
}

# Test basic dump (JSON Line)
my $output = `$perl -Ilib $bin dump $tc_string`;
ok( $output, "Got output from CLI dump" );

my $json_obj = decode_helper($output);
ok( $json_obj, "Output is valid JSON" );
is( $json_obj->{version}, 2, "Parsed version is correct" );

# Test pretty print
my $pretty_output = `$perl -Ilib $bin dump --pretty $tc_string`;
like(
    $pretty_output,
    qr/"version"\s*:\s*2/,
    "Pretty output contains version"
);
like( $pretty_output, qr/\n    "/, "Pretty output contains indentation" );

# Test short -p alias
my $short_p_output = `$perl -Ilib $bin dump -p $tc_string`;
my $short_p_json   = decode_helper($short_p_output);
my $pretty_json    = decode_helper($pretty_output);
is_deeply( $short_p_json, $pretty_json,
    "Short -p alias produces logically same output as --pretty" );

# Test array output
my $array_output = `$perl -Ilib $bin dump --json-array $tc_string $tc_string`;
my $array_json   = decode_helper($array_output);
ok( $array_json, "Output is valid JSON array" );
is( ref($array_json),     'ARRAY', "Root is an array" );
is( scalar(@$array_json), 2,       "Array contains two elements" );

# Test STDIN (using Perl to avoid shell-specific echo/heredoc issues)
my $stdin_output = `$perl -e "print '$tc_string'" | $perl -Ilib $bin dump`;

my $stdin_json = decode_helper($stdin_output);
ok( $stdin_json, "Parsed from STDIN correctly" )
  or diag("Output was: $stdin_output");
is( $stdin_json->{version}, 2, "Parsed version from STDIN is correct" );

# Test compact output
my $compact_output = `$perl -Ilib $bin dump --compact $tc_string`;
my $compact_json   = decode_helper($compact_output);
ok( $compact_json, "Got compact output" );
is( ref( $compact_json->{purpose}{consents} ), 'ARRAY',
    "Compact output uses array for purpose consents"
);

# Test Error Handling
my $invalid_str = "INVALID_STRING_XYZ";
my $json_false =
  $json_pkg->can('false') ? $json_pkg->false() : JSON::PP::false();

# 1. Default Error JSON
my $err_output = `$perl -Ilib $bin dump $invalid_str 2>$devnull`;
my $err_json   = decode_helper($err_output);
ok( $err_json, "Invalid string produces JSON error object" );
is( $err_json->{success},   $json_false,       "Error object success is false" );
is( $err_json->{tc_string}, $invalid_str, "Error object includes raw string" );

# 2. --ignore-errors
my $ignore_output =
  `$perl -Ilib $bin dump --ignore-errors $invalid_str 2>$devnull`;
is( $ignore_output, "", "--ignore-errors produces no output for bad string" );

# 3. --fail-fast
my $ff_output = `$perl -Ilib $bin dump --fail-fast $invalid_str 2>$devnull`;
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

my $e2s_stderr_json = decode_helper($e2s_stderr);
ok( $e2s_stderr_json, "--errors-to-stderr routes JSON to stderr" )
  or diag("Stderr was: $e2s_stderr");

done_testing();
