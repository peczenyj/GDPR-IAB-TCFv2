use ExtUtils::MakeMaker;
 
WriteMakefile(
    ABSTRACT         => 'gdpr iab tcf v2 consent string decoder',
    AUTHOR           => 'Tiago Peczenyj <tiago.peczenyj@gmail.com>',
    NAME             => 'GDPR::IAB::TCFv2',
    VERSION_FROM     => 'lib/GDPR/IAB/TCFv2.pm',
    MIN_PERL_VERSION => 5.012,
    LICENSE          => "perl_5",
    TEST_REQUIRES => {
        'Test::Exception' => 0,
        'Test::More'      => 0,
    },
    SKIP => [ qw<.github> ],
    (eval { ExtUtils::MakeMaker->VERSION(6.46) } ? (META_MERGE => {
      'meta-spec' => { version => 2 },
      resources => {
          repository => {
              type => 'git',
              url  => 'https://github.com/peczenyj/GDPR-IAB-TCFv2.git',
              web  => 'https://github.com/peczenyj/GDPR-IAB-TCFv2',
          },
      }})
   : ()
  ),
);
