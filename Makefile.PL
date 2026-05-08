use ExtUtils::MakeMaker;

WriteMakefile(
  NAME             => 'GDPR::IAB::TCFv2',
  AUTHOR           => 'Tiago Peczenyj <tiago.peczenyj+gdpr-iab-tcfv2@gmail.com>',
  LICENSE          => "perl_5",
  ABSTRACT_FROM    => 'lib/GDPR/IAB/TCFv2.pm',
  VERSION_FROM     => 'lib/GDPR/IAB/TCFv2.pm',
  MIN_PERL_VERSION => 5.008,
  EXE_FILES        => ['bin/iabtcfv2'],
  TEST_REQUIRES    => {

    # JSON::PP and Time::Piece are listed here (rather than under
    # PREREQ_PM) because they are runtime deps of the optional
    # CMPValidator feature only. The lib/ side lazy-requires them
    # at first use; we still need them installed in the test
    # environment so t/14-cmp-validator.t can exercise the feature.
    # End-user installs that opt into CMPValidator should also pull
    # them in via the META `recommends` block.
    'JSON::PP'               => 0,
    'Time::Piece'            => 0,
    'Test::Exception'        => 0.43,
    'Test::More'             => 0.94,
    'Test::Pod'              => 0,
    'Test::Warn'             => 0.30,
    'IO::Compress::Gzip'     => 0,
    'IO::Uncompress::Gunzip' => 0,
  },
  (
    eval { ExtUtils::MakeMaker->VERSION(6.46) }
    ? (
      META_MERGE => {
        'meta-spec'    => {version => 2},
        dynamic_config => 0,
        provides       => _get_provides(),
        resources      => {
          homepage   => 'https://github.com/peczenyj/GDPR-IAB-TCFv2',
          repository => {
            type => 'git',
            url  => 'https://github.com/peczenyj/GDPR-IAB-TCFv2.git',
            web  => 'https://github.com/peczenyj/GDPR-IAB-TCFv2',
          },
          x_security_policy => 'https://github.com/peczenyj/GDPR-IAB-TCFv2/blob/devel/SECURITY.md',
          bugtracker        => {web => 'https://github.com/peczenyj/GDPR-IAB-TCFv2/issues'},
        },
        recommends => {

          # CMPValidator opt-in feature: lazy-required at first
          # use, with a clear croak when missing. Listed here
          # so toolchains that honor `recommends` install them
          # automatically; base parser users do not pay the
          # dep cost.
          'JSON::PP'    => 0,
          'Time::Piece' => 0,
          'HTTP::Tiny'  => 0,

          'JSON'               => 0,
          'JSON::XS'           => 0,
          'DateTimeX::TO_JSON' => 0,
        },
        x_authority => 'cpan:PACMAN',
      }
      )
    : ()
  ),
);

sub _get_provides {
  use File::Find;
  my %provides;
  find(
    {
      wanted => sub {
        return unless /\.pm$/;
        my $file   = $File::Find::name;
        my $module = $file;
        $module =~ s|^lib/||;
        $module =~ s|/|::|g;
        $module =~ s|\.pm$||;
        my $v = MM->parse_version($file);
        $provides{$module} = {file => $file, version => $v || "0"};
      },
      no_chdir => 1
    },
    "lib"
  );
  return \%provides;
}

sub MY::postamble {
  return <<'EOF';
lint:
	perlcritic -profile .perlcriticrc lib bin t xt

tidy:
	perltidy -b -pro=.perltidyrc Makefile.PL $$(find lib bin t xt bench -type f \( -name "*.pm" -o -name "*.t" -o -name "*.pl" -o -name "iabtcfv2" \) 2>/dev/null)
EOF
}

