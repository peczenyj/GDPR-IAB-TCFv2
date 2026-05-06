use strict;
use warnings;
use Test::More;
use GDPR::IAB::TCFv2;
use File::Spec;

# Test TC strings
my $tc_with_res = 'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA'
  ;    # Core + Restrictions
my $tc_with_disc = $tc_with_res . '.IAAA';    # Core + Res + Discl (empty)
my $tc_full =
  'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA.ILrtR_G__bXlv-bb36ftkeYxf9_hr7sQxBgbJs24FzLvW7JwX32E7NEzatqYKmRIAu3TBIQNtHJjURVChKIgVrzDsaEyUoTtKJ-BkiHMRY2NYCFxvm4tjWQCZ5vr_91d9mT-N7dr-2dzyy7hnv3a9_-S1WJidKYetHfv8bBKT-_IU9_x-_4v4_N7pE2-eS1v_tGvt639-4vP_dpvxt-7yffz____73_e7X__d_______Xf_7____________4AAA';

subtest 'Predicates' => sub {

    # TCF v2.3 string without DV segment (CP188...)
    my $tc_basic =
      'CP188cAQKFpAAAHABBENBSFsAP_gAEPgAAiQKqNX_H__bW9r8X73aft0eY1P9_j77uQxBhfJE-4FzLvW_JwXx2ExNA36tqIKmRIEu3bBIQNlHJHUTVigaogVryHMak2cpTNKJ6BkiFMRM2dYCF5vm4tj-QKY5_r993dx2D-t_dv83dzyz81Hn3f5_2e0eLCdQ5-tDfv9bROb-9IPd_78v4v8_l_rk2_eT1n_tevr7D_-ft8__XW_9_fff_9Pn_-uB_-_3_vf_EFUwCTDQqIA-wJCQg0DCKBACoKwgIoFAQAAJA0QEAJgwKdgYALrCRACAFAAMEAIAAQZAAgAAAgAQiACQAoEAAEAgUAAYAEAwEABAwAAgAsBAIAAQHQMUwIIFAsIEjMioUwIQoEggJbKhBICgQVwhCLPAIgERMFAAgAAAVgACAsFgcSSAlQkECXUG0AABAAgFEIFQgk9MAAwJmy1B4MG0ZWmAYPmCRDTAMgCIIyEAAAA.f_wACHwAAAAA';
    my $c1 = GDPR::IAB::TCFv2->Parse($tc_basic);
    ok( !$c1->has_vendor_disclosure, 'No disclosure segment' );

    my $c2 = GDPR::IAB::TCFv2->Parse($tc_with_res);
    ok( $c2->has_publisher_restrictions, 'Has restrictions' );

    my $c3 = GDPR::IAB::TCFv2->Parse($tc_with_disc);
    ok( $c3->has_vendor_disclosure, 'Has disclosure segment' );

    # Test has_publisher_restrictions on a string that might not have it
    my $tc_minimal = 'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA';
    my $c_min      = GDPR::IAB::TCFv2->Parse($tc_minimal);
    ok( !$c_min->has_publisher_restrictions,
        'No restrictions on minimal string'
    );
};

subtest 'Robustness: Truncated segments' => sub {
    use Test::Exception;

    # Using the valid disclosure segment from $tc_full
    my $segment_disc =
      'ILrtR_G__bXlv-bb36ftkeYxf9_hr7sQxBgbJs24FzLvW7JwX32E7NEzatqYKmRIAu3TBIQNtHJjURVChKIgVrzDsaEyUoTtKJ-BkiHMRY2NYCFxvm4tjWQCZ5vr_91d9mT-N7dr-2dzyy7hnv3a9_-S1WJidKYetHfv8bBKT-_IU9_x-_4v4_N7pE2-eS1v_tGvt639-4vP_dpvxt-7yffz____73_e7X__d_______Xf_7____________4AAA';

    # Valid disclosure
    my $tc_valid = $tc_with_res . '.' . $segment_disc;
    lives_ok { GDPR::IAB::TCFv2->Parse($tc_valid) }
    'Valid disclosure segment lives';

    # Truncated disclosure: remove most of the bitfield
    # This segment uses MaxId=1502.
    # Bits needed: 3 + 16 + 1 + 1502 = 1522 bits.
    # 1522 bits / 6 = 254 chars.
    # Truncate to 48 chars (multiple of 4, 288 bits).
    my $tc_truncated = $tc_with_res . '.' . substr( $segment_disc, 0, 48 );
    throws_ok { GDPR::IAB::TCFv2->Parse($tc_truncated) }
    qr/requires a consent string of at least 1502 bits/,
      'Croaks on truncated bitfield disclosure';
};

subtest 'vendor_id filter in TO_JSON' => sub {
    my $c = GDPR::IAB::TCFv2->Parse($tc_full);

    # Vendor 284 is present in consents and disclosed
    my $json_284 = $c->TO_JSON( vendor_id => 284 );

    # Consents should only have 284
    is_deeply( [ sort { $a <=> $b } keys %{ $json_284->{vendor}{consents} } ],
        [284], 'Filtered consents' );
    is_deeply( [ sort { $a <=> $b } keys %{ $json_284->{vendor}{disclosed} } ],
        [284], 'Filtered disclosed' );

    # Publisher restrictions should only show 32 (from $tc_with_res baseline)
    my $c_res    = GDPR::IAB::TCFv2->Parse($tc_with_res);
    my $json_res = $c_res->TO_JSON( vendor_id => 32 );
    is_deeply( [ keys %{ $json_res->{publisher}{restrictions}{7} } ], [32],
        'Filtered publisher restrictions' );

    # Vendor 9999 is NOT present
    my $json_9999 = $c->TO_JSON( vendor_id => 9999 );
    is_deeply( $json_9999->{vendor}{consents}, {}, 'Empty filtered consents' );
};

subtest 'CLI --vendor-id option' => sub {
    my $bin  = File::Spec->catfile( 'bin', 'iabtcfv2' );
    my $perl = $^X;

    my $out = `$perl -Ilib $bin dump --vendor-id 284 $tc_full`;
    like( $out, qr/"284":true/, 'CLI output contains target vendor' );
    unlike( $out, qr/"23":true/, 'CLI output does NOT contain other vendors' );
};

subtest 'CLI --strict option' => sub {
    my $bin  = File::Spec->catfile( 'bin', 'iabtcfv2' );
    my $perl = $^X;

    # TCF v2.3 string without DV segment (CP188...)
    my $tc_v23_no_dv =
      'CP188cAQKFpAAAHABBENBSFsAP_gAEPgAAiQKqNX_H__bW9r8X73aft0eY1P9_j77uQxBhfJE-4FzLvW_JwXx2ExNA36tqIKmRIEu3bBIQNlHJHUTVigaogVryHMak2cpTNKJ6BkiFMRM2dYCF5vm4tj-QKY5_r993dx2D-t_dv83dzyz81Hn3f5_2e0eLCdQ5-tDfv9bROb-9IPd_78v4v8_l_rk2_eT1n_tevr7D_-ft8__XW_9_fff_9Pn_-uB_-_3_vf_EFUwCTDQqIA-wJCQg0DCKBACoKwgIoFAQAAJA0QEAJgwKdgYALrCRACAFAAMEAIAAQZAAgAAAgAQiACQAoEAAEAgUAAYAEAwEABAwAAgAsBAIAAQHQMUwIIFAsIEjMioUwIQoEggJbKhBICgQVwhCLPAIgERMFAAgAAAVgACAsFgcSSAlQkECXUG0AABAAgFEIFQgk9MAAwJmy1B4MG0ZWmAYPmCRDTAMgCIIyEAAAA';

    my $out_lenient = `$perl -Ilib $bin dump $tc_v23_no_dv`;
    like( $out_lenient, qr/"tc_string":/i, 'Lenient mode (default) succeeds' );

    my $out_strict = `$perl -Ilib $bin dump --strict $tc_v23_no_dv`;
    like(
        $out_strict,
        qr/Disclosed Vendors segment is mandatory/,
        'Strict mode fails for v2.3 without DV'
    );
};

done_testing();
