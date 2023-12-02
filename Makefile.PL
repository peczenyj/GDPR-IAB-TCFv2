use ExtUtils::MakeMaker;
 
WriteMakefile(
    ABSTRACT         => 'gdpr iab tcf v2 consent string decoder',
    AUTHOR           => 'Tiago Peczenyj <tiago.peczenyj@gmail.com>',
    NAME             => 'GDPR::IAB::TCFv2',
    VERSION_FROM     => 'lib/GDPR/IAB/TCFv2.pm',
    MIN_PERL_VERSION => 5.012,
    LICENSE          => "mit",
    TEST_REQUIRES => {
        'Test::Exception' => 0,
        'Test::More'      => 0,
    },
    VERSION => '0.001',
);
