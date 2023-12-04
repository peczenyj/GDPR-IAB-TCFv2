use Test::More tests => 14;

BEGIN {
    use_ok('GDPR::IAB::TCFv2::BitUtils');
    use_ok('GDPR::IAB::TCFv2::BitField');
    use_ok('GDPR::IAB::TCFv2::RangeSection');
    use_ok('GDPR::IAB::TCFv2::RangeConsent');
    use_ok('GDPR::IAB::TCFv2');
}

require_ok 'GDPR::IAB::TCFv2::BitUtils';
require_ok 'GDPR::IAB::TCFv2::BitField';
require_ok 'GDPR::IAB::TCFv2::RangeSection';
require_ok 'GDPR::IAB::TCFv2::RangeConsent';
require_ok 'GDPR::IAB::TCFv2';

isa_ok 'GDPR::IAB::TCFv2::BitUtils', 'Exporter';

my @methods = qw<new max_vendor_id vendor_consent>;

can_ok 'GDPR::IAB::TCFv2::BitField',     @methods;
can_ok 'GDPR::IAB::TCFv2::RangeSection', @methods;

can_ok 'GDPR::IAB::TCFv2::RangeConsent', 'new', 'contains';
