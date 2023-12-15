use strict;
use warnings;
use Test::More;

BEGIN {
    use_ok('GDPR::IAB::TCFv2::Constants::Purpose');
    use_ok('GDPR::IAB::TCFv2::Constants::SpecialFeature');
    use_ok('GDPR::IAB::TCFv2::Constants::RestrictionType');
    use_ok('GDPR::IAB::TCFv2::BitUtils');
    use_ok('GDPR::IAB::TCFv2::BitField');
    use_ok('GDPR::IAB::TCFv2::PublisherRestrictions');
    use_ok('GDPR::IAB::TCFv2::RangeSection');
    use_ok('GDPR::IAB::TCFv2');
}

require_ok('GDPR::IAB::TCFv2::Constants::Purpose');
require_ok('GDPR::IAB::TCFv2::Constants::SpecialFeature');
require_ok('GDPR::IAB::TCFv2::Constants::RestrictionType');
require_ok 'GDPR::IAB::TCFv2::BitUtils';
require_ok 'GDPR::IAB::TCFv2::BitField';
require_ok('GDPR::IAB::TCFv2::PublisherRestrictions');
require_ok 'GDPR::IAB::TCFv2::RangeSection';
require_ok 'GDPR::IAB::TCFv2';

subtest "check interfaces" => sub {
    isa_ok 'GDPR::IAB::TCFv2::BitUtils',                   'Exporter';
    isa_ok 'GDPR::IAB::TCFv2::Constants::Purpose',         'Exporter';
    isa_ok 'GDPR::IAB::TCFv2::Constants::SpecialFeature',  'Exporter';
    isa_ok 'GDPR::IAB::TCFv2::Constants::RestrictionType', 'Exporter';

    my @role_methods = qw<Parse contains TO_JSON max_id>;

    can_ok 'GDPR::IAB::TCFv2::BitField',              @role_methods;
    can_ok 'GDPR::IAB::TCFv2::RangeSection',          @role_methods;
    can_ok 'GDPR::IAB::TCFv2::PublisherRestrictions', @role_methods;

    can_ok 'GDPR::IAB::TCFv2::RangeSection', qw<all>;

    done_testing;
};

diag("GDPR::IAB::TCFv2/$GDPR::IAB::TCFv2::VERSION");

done_testing;
