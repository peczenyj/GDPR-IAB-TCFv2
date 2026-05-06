use strict;
use warnings;
use Test::More;
use GDPR::IAB::TCFv2;
use File::Spec;

# Test TC strings
my $tc_basic =
  'CP188cAQKFpAAAHABBENBSFsAP_gAEPgAAiQKqNX_H__bW9r8X73aft0eY1P9_j77uQxBhfJE-4FzLvW_JwXx2ExNA36tqIKmRIEu3bBIQNlHJHUTVigaogVryHMak2cpTNKJ6BkiFMRM2dYCF5vm4tj-QKY5_r993dx2D-t_dv83dzyz81Hn3f5_2e0eLCdQ5-tDfv9bROb-9IPd_78v4v8_l_rk2_eT1n_tevr7D_-ft8__XW_9_fff_9Pn_-uB_-_3_vf_EFUwCTDQqIA-wJCQg0DCKBACoKwgIoFAQAAJA0QEAJgwKdgYALrCRACAFAAMEAIAAQZAAgAAAgAQiACQAoEAAEAgUAAYAEAwEABAwAAgAsBAIAAQHQMUwIIFAsIEjMioUwIQoEggJbKhBICgQVwhCLPAIgERMFAAgAAAVgACAsFgcSSAlQkECXUG0AABAAgFEIFQgk9MAAwJmy1B4MG0ZWmAYPmCRDTAMgCIIyEAAAA.f_wACHwAAAAA';
my $tc_with_res = 'COwAdDhOwAdDhN4ABAENAPCgAAQAAv___wAAAFP_AAp_4AI6ACACAA'
  ;    # Vendor 32 has res type 1 on purpose 7
my $tc_with_disc = $tc_with_res . '.IAAA';
my $tc_full =
  'CQa0q5gQa0q5gAcABBESCEFsAP_gAEPgAChQLutR_G__bWlr-bb3aftkeYxP9_hr7sQxBgbJk24FzLvW7JwXx2E5NAzatqIKmRIAu3TBIQNlHJDURVCgKIgVryDMaEyUoTNKJ6BkiFMRI2NYCFxvm4tjWQCY5vr99lc1mB-N7dr82dzyy6hHn3a5_2S1WJCdIYetDfv8ZBKT-9IEd_x8v4v4_F7pE2-eS1n_pGvp6j9-YnM_dBmxt-bSffzPn__rl_e7X_vd_n37v94XH77v____f_-7___2YLvAAmGhUQRlkQIBAoGEECABQVhABQIAgAASBogIATBgU5AwAXWEyAEAKAAYIAQAAgwABAAAJAAhEAFABAIAAIBAoAAwAIAgIAGBgADABYiAQAAgOgYpgQQCBYAJGZVBpgSgAJBAS2VCCQDAgrhCEWeAQQIiYKAAAEAAoAAAB4LAQkkBKxIIAuIJoAACAAAKIECBFIWYAgqDNFoLwJOoyNMAwfMEySnQZAEwRkZJsQm_CYeKQohQQ5AbFLMAdMAA.f_wACHwAAAAA.ILvNR_G__bXlv-bb36ftkeYxf9_hr7sQxBgbJs24FzLvW7JwX32E7NEzatqYKmRIAu3TBIQNtHJjURVChKIgVrzDsaEyUoTtKJ-BkiHMRY2NYCFxvm4tjWQCZ5vr_91d9mT-N7dr-2dzyy7hnv3a9_-S1WJidKYetHfv8ZBKT-_IU9_x-_4v4_N7pE2-eS1v_tGvt639-4vP_dpvxt-7yffz____73_e7X__d_______Xf_7_____________cAA';

subtest 'Predicates' => sub {
    my $c1 = GDPR::IAB::TCFv2->Parse($tc_basic);
    ok( !$c1->has_vendor_disclosure, 'No disclosure segment' );

    my $c2 = GDPR::IAB::TCFv2->Parse($tc_with_res);
    ok( $c2->has_publisher_restrictions, 'Has restrictions' );

    my $c3 = GDPR::IAB::TCFv2->Parse($tc_with_disc);
    ok( $c3->has_vendor_disclosure, 'Has disclosure segment' );
};

subtest 'vendor_id filter in TO_JSON' => sub {
    my $c = GDPR::IAB::TCFv2->Parse($tc_full);

    # Vendor 284 is present in consents and disclosed
    my $json_284 = $c->TO_JSON( vendor_id => 284 );
    is_deeply(
        [ sort { $a <=> $b } keys %{ $json_284->{vendor}{consents} } ],
        [284], 'Filtered consents'
    );
    is_deeply(
        [ sort { $a <=> $b } keys %{ $json_284->{vendor}{disclosed} } ],
        [284], 'Filtered disclosed'
    );

    # Use $tc_with_res to test filtered restrictions
    my $c_res    = GDPR::IAB::TCFv2->Parse($tc_with_res);
    my $json_res = $c_res->TO_JSON( vendor_id => 32 );
    is_deeply(
        [ keys %{ $json_res->{publisher}{restrictions}{7} } ], [32],
        'Filtered publisher restrictions'
    );

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

done_testing();
