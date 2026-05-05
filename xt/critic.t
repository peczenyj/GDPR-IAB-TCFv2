use strict;
use warnings;
use Test::More;

eval "use Test::Perl::Critic (-profile => '.perlcriticrc')";
plan skip_all => "Test::Perl::Critic required for criticizing" if $@;

# Only run critic on production code to match previous CI behavior
all_critic_ok('lib');
