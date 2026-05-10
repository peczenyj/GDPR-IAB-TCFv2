use strict;
use warnings;
use Test::More;

eval "use Test::Version";
plan skip_all => "Test::Version required for version coherence checks"
  if $@;

Test::Version->import(qw<version_all_ok>);

# Enforces:
#   * has_version => 1: every .pm declares a $VERSION literal.
#   * consistent  => 1: every $VERSION matches the dist version.
# Catches the kind of cross-package drift that broke v0.400's PAUSE
# indexation (CMPValidator regressed from 0.001 to "0" -> PAUSE refused
# to re-index).
version_all_ok({ has_version => 1, consistent => 1 });
done_testing();
