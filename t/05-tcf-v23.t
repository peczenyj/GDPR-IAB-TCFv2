use strict;
use warnings;

use Test::More;
use Test::Exception;

use GDPR::IAB::TCFv2;

my $tc_v23 = 'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA.ILrtR_G__bXlv-bb36ftkeYxf9_hr7sQxBgbJs24FzLvW7JwX32E7NEzatqYKmRIAu3TBIQNtHJjURVChKIgVrzDsaEyUoTtKJ-BkiHMRY2NYCFxvm4tjWQCZ5vr_91d9mT-N7dr-2dzyy7hnv3a9_-S1WJidKYetHfv8bBKT-_IU9_x-_4v4_N7pE2-eS1v_tGvt639-4vP_dpvxt-7yffz____73_e7X__d_______Xf_7____________4AAA';

subtest "TCF v2.3 segments" => sub {
    my $consent;
    lives_ok {
        $consent = GDPR::IAB::TCFv2->Parse($tc_v23);
    } 'should parse v2.3 string with disclosed vendors';

    is $consent->version, 2, 'version should be 2';

    # Disclosed vendors check
    ok $consent->disclosed_vendor(284), 'Weborama (284) should be disclosed';
    ok !$consent->disclosed_vendor(9999), 'vendor 9999 should NOT be disclosed';
    
    # Allowed vendors check (not present in this string)
    ok !$consent->allowed_vendor(284), 'vendor 284 should NOT be in allowed vendors segment (segment missing)';
};

subtest "duplicate segment check" => sub {
    my $duplicate_string = $tc_v23 . '.ILrtR_G__bXlv-bb36ftkeYxf9_hr7sQxBgbJs24FzLvW7JwX32E7NEzatqYKmRIAu3TBIQNtHJjURVChKIgVrzDsaEyUoTtKJ-BkiHMRY2NYCFxvm4tjWQCZ5vr_91d9mT-N7dr-2dzyy7hnv3a9_-S1WJidKYetHfv8bBKT-_IU9_x-_4v4_N7pE2-eS1v_tGvt639-4vP_dpvxt-7yffz____73_e7X__d_______Xf_7____________4AAA';
    throws_ok {
        GDPR::IAB::TCFv2->Parse($duplicate_string);
    } qr/duplicate segment type 1/, 'should throw exception for duplicate segment type 1';
};

subtest "TO_JSON with v2.3" => sub {
    my $consent = GDPR::IAB::TCFv2->Parse($tc_v23);
    
    my $json = $consent->TO_JSON;
    ok exists $json->{vendor}->{disclosed}, 'disclosed vendors should be in TO_JSON';
    ok !exists $json->{vendor}->{allowed}, 'allowed vendors should NOT be in TO_JSON (missing segment)';
    ok defined $json->{vendor}->{disclosed}, 'disclosed vendors should be defined';
};

done_testing;
