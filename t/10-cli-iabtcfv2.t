use strict;
use warnings;
use Test::More;

eval { require JSON; 1 }
  or eval { require JSON::PP; 1 }
  or plan skip_all => 'JSON or JSON::PP required for this test';

my $json_pkg = JSON->can('new') ? 'JSON' : 'JSON::PP';

use File::Spec;
my $perl = $^X;
my $bin  = File::Spec->catfile( 'bin', 'iabtcfv2' );

sub decode_helper {
    my $json_str = shift;
    return unless $json_str;
    eval { $json_pkg->new->decode($json_str) };
}

# 1. Basic dump
my $out =
  `$perl -Ilib $bin dump CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA`;
ok( $out, "Got output from CLI dump" );

my $data = decode_helper($out);
ok( $data, "Output is valid JSON" );
is( $data->{version}, 2, "Parsed version is correct" );

# 2. Pretty print
my $pretty_out =
  `$perl -Ilib $bin dump --pretty CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA`;
like( $pretty_out, qr/"version"\s*:\s*2/, "Pretty output contains version" );

# regex should be flexible for 3 or 4 spaces
like(
    $pretty_out, qr/^\s{3,4}"version"/m,
    "Pretty output contains indentation"
);

my $p_alias_out =
  `$perl -Ilib $bin dump -p CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA`;

# Compare logically since key order might differ
my $pretty_data  = decode_helper($pretty_out);
my $p_alias_data = decode_helper($p_alias_out);
is_deeply(
    $p_alias_data,
    $pretty_data,
    "Short -p alias produces logically same output as --pretty"
);

# 3. JSON Array
my $array_out =
  `$perl -Ilib $bin dump --json-array CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA`;
my $array_data = decode_helper($array_out);
ok( $array_data, "Output is valid JSON array" );
is( ref($array_data),     'ARRAY', "Root is an array" );
is( scalar(@$array_data), 2,       "Array contains two elements" );

# 4. STDIN and Error Handling (Skipped on Windows due to shell redirection issues)
SKIP: {
    skip "Shell redirection tests are brittle on Windows", 7
      if $^O eq 'MSWin32';

    # 4. STDIN
    my $tc_string =
      "CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA";
    my $stdin_file = File::Spec->catfile( 't', 'test_stdin.tmp' );
    open my $sfh, '>', $stdin_file or die $!;
    print $sfh $tc_string;
    close $sfh;

    my $stdin_out = `$perl -Ilib $bin dump < $stdin_file`;
    unlink $stdin_file;

    my $stdin_data = decode_helper($stdin_out);
    ok( $stdin_data, "Parsed from STDIN correctly" );
    is( $stdin_data->{version}, 2, "Parsed version from STDIN is correct" );

    # 6. Error handling
    my $bad_string = "INVALID_STRING";
    my $nul        = '/dev/null';
    my $err_out    = `$perl -Ilib $bin dump $bad_string 2>$nul`;
    my $err_data   = decode_helper($err_out);
    ok( $err_data, "Invalid string produces JSON error object" );
    is( $err_data->{success},
        $json_pkg->can('false') ? $json_pkg->false : 0,
        "Error object success is false"
    );
    is( $err_data->{tc_string}, $bad_string,
        "Error object includes raw string"
    );

    my $ignore_out =
      `$perl -Ilib $bin dump --ignore-errors $bad_string 2>$nul`;
    ok( !$ignore_out, "--ignore-errors produces no output for bad string" );

    system("$perl -Ilib $bin dump --fail-fast $bad_string 2>$nul");
    isnt( $?, 0, "--fail-fast exits with non-zero code" );
}

# 5. Compact
my $compact_out =
  `$perl -Ilib $bin dump --compact CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA`;
my $compact_data = decode_helper($compact_out);
ok( $compact_data, "Got compact output" );
is( ref( $compact_data->{purpose}{consents} ),
    'ARRAY',
    "Compact output uses array for purpose consents"
);

# 7. Errors to Stderr (with --quiet to suppress human warnings)
my $stderr_file = File::Spec->catfile( 't', 'test_stderr.tmp' );
my $bad_string  = "INVALID_STRING";
my $e2s_stdout =
  `$perl -Ilib $bin dump --quiet --errors-to-stderr $bad_string 2>$stderr_file`;
ok( !$e2s_stdout, "--errors-to-stderr stdout is empty for bad string" );

my $e2s_stderr;
if ( -f $stderr_file ) {
    open my $fh, '<', $stderr_file or die "Can't read $stderr_file: $!";
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

    # 4. Version
    my $version_output = `$perl -Ilib $bin --version`;
    like(
        $version_output, qr/iabtcfv2 version \d+\.\d+/,
        "Version output is correct"
    );
    my $short_version_output = `$perl -Ilib $bin -V`;
    is( $short_version_output, $version_output, "-V is alias for --version" );
};

done_testing();
