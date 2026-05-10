use strict;
use warnings;
use Test::More;

eval "use Test::Version 1.001001 qw<version_all_ok>, " . "{ has_version => 1, consistent => 1 }";
plan skip_all => "Test::Version 1.001001+ required for version coherence checks" if $@;

# Enforces:
#   * has_version: every .pm declares a $VERSION literal.
#   * consistent: every $VERSION matches the dist version.
# Catches the kind of cross-package drift that broke v0.400's PAUSE
# indexation (CMPValidator regressed from 0.001 to "0" -> PAUSE refused
# to re-index).
version_all_ok();
done_testing();
