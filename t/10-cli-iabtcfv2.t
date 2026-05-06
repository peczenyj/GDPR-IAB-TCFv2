use strict;
use warnings;
use Test::More;

eval { require JSON; 1 }
  or eval { require JSON::PP; 1 }
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
like( $pretty_output, qr/\n\s+"/, "Pretty output contains indentation" );

# Test short -p alias
my $short_p_output = `$perl -Ilib $bin dump -p $tc_string`;
my $short_p_json   = decode_helper($short_p_output);
my $pretty_json    = decode_helper($pretty_output);
is_deeply(
    $short_p_json, $pretty_json,
    "Short -p alias produces logically same output as --pretty"
);

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
is( $err_json->{success},   $json_false,  "Error object success is false" );
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

# Test Help System
subtest 'Help System' => sub {

    # 1. Global Help
    my $global_help = `$perl -Ilib $bin --help`;
    like( $global_help, qr/SUBCOMMANDS/i, "Global help lists subcommands" );
    like( $global_help, qr/dump/i,        "Global help mentions 'dump'" );
    like( $global_help, qr/validate/i,    "Global help mentions 'validate'" );

    # 2. Subcommand Help (dump)
    my $dump_help = `$perl -Ilib $bin dump --help`;
    like( $dump_help, qr/DUMP/i,      "Subcommand help header found" );
    like( $dump_help, qr/--compact/i, "Subcommand help lists --compact" );
    like(
        $dump_help, qr/--json-array/i,
        "Subcommand help lists --json-array"
    );
    like( $dump_help, qr/Examples/i, "Subcommand help shows examples" );

    # 3. Help Subcommand
    my $help_cmd = `$perl -Ilib $bin help dump`;
    is( $help_cmd, $dump_help, "'help dump' is same as 'dump --help'" );
};

# Test Version Option
subtest 'Version Option' => sub {
    my $version_output = `$perl -Ilib $bin --version`;
    like(
        $version_output, qr/iabtcfv2 version \d+\.\d+/,
        "--version prints version string"
    );

    my $short_version_output = `$perl -Ilib $bin -V`;
    is( $short_version_output, $version_output,
        "-V is alias for --version"
    );
};

# Test Short Option Bundling and = syntax
subtest 'Short option bundling and = value syntax' => sub {

    # Bundled boolean flags: -pq is parsed as --pretty --quiet.
    # `--pretty` produces multi-line indented JSON, which is the easiest
    # observable side effect to assert on.
    my $bundled_flags_out  = `$perl -Ilib $bin dump -pq $tc_string`;
    my $bundled_flags_data = decode_helper($bundled_flags_out);
    ok( $bundled_flags_data, '-pq produces valid JSON' );
    like(
        $bundled_flags_out, qr/\n\s+"/,
        '-pq enables --pretty (multi-line output)'
    );

    # Bundled flag + value-taking short: -pv 1 is --pretty --vendor-id 1.
    # Compare logically against the canonical long-form invocation so the
    # assertion doesn't depend on which fields are populated for the chosen
    # vendor in the fixture.
    my $bundled_value_data =
      decode_helper(`$perl -Ilib $bin dump -pv 1 $tc_string`);
    my $longform_data =
      decode_helper(`$perl -Ilib $bin dump --pretty --vendor-id 1 $tc_string`);
    is_deeply(
        $bundled_value_data, $longform_data,
        '-pv 1 produces the same data as --pretty --vendor-id 1'
    );

    # GNU-style --opt=value: --vendor-id=1 must behave identically to
    # --vendor-id 1.
    my $eq_data =
      decode_helper(`$perl -Ilib $bin dump --vendor-id=1 $tc_string`);
    my $space_data =
      decode_helper(`$perl -Ilib $bin dump --vendor-id 1 $tc_string`);
    is_deeply(
        $eq_data, $space_data,
        '--vendor-id=1 is parsed identically to --vendor-id 1'
    );
};

# Test short aliases -c (compact) and -s (strict)
subtest 'Short aliases -c (compact) and -s (strict)' => sub {

    # -c == --compact: assert by comparing decoded data against the long form.
    my $c_data = decode_helper(`$perl -Ilib $bin dump -c $tc_string`);
    my $long_data =
      decode_helper(`$perl -Ilib $bin dump --compact $tc_string`);
    is_deeply( $c_data, $long_data, '-c produces the same data as --compact' );
    is( ref( $c_data->{purpose}{consents} ), 'ARRAY',
        '-c enables compact form (purpose consents as array)'
    );

    # -s == --strict: a TCF v2.3 string without Disclosed Vendors segment
    # must be rejected with the standard "Disclosed Vendors segment is
    # mandatory" message.  --quiet keeps the warn off CI.
    my $tc_v23_no_dv =
      'CP188cAQKFpAAAHABBENBSFsAP_gAEPgAAiQKqNX_H__bW9r8X73aft0eY1P9_j77uQxBhfJE-4FzLvW_JwXx2ExNA36tqIKmRIEu3bBIQNlHJHUTVigaogVryHMak2cpTNKJ6BkiFMRM2dYCF5vm4tj-QKY5_r993dx2D-t_dv83dzyz81Hn3f5_2e0eLCdQ5-tDfv9bROb-9IPd_78v4v8_l_rk2_eT1n_tevr7D_-ft8__XW_9_fff_9Pn_-uB_-_3_vf_EFUwCTDQqIA-wJCQg0DCKBACoKwgIoFAQAAJA0QEAJgwKdgYALrCRACAFAAMEAIAAQZAAgAAAgAQiACQAoEAAEAgUAAYAEAwEABAwAAgAsBAIAAQHQMUwIIFAsIEjMioUwIQoEggJbKhBICgQVwhCLPAIgERMFAAgAAAVgACAsFgcSSAlQkECXUG0AABAAgFEIFQgk9MAAwJmy1B4MG0ZWmAYPmCRDTAMgCIIyEAAAA';

    my $s_out = `$perl -Ilib $bin dump -s --quiet $tc_v23_no_dv`;
    like(
        $s_out, qr/Disclosed Vendors segment is mandatory/,
        '-s enables --strict (rejects v2.3 without Disclosed Vendors)'
    );

    # Bundled new shorts: -cp must produce the same data as --compact --pretty.
    my $bundled_cp_data =
      decode_helper(`$perl -Ilib $bin dump -cp $tc_string`);
    my $longform_cp_data =
      decode_helper(`$perl -Ilib $bin dump --compact --pretty $tc_string`);
    is_deeply(
        $bundled_cp_data, $longform_cp_data,
        '-cp produces the same data as --compact --pretty'
    );
};

done_testing();
