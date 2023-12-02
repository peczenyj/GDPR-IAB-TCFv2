use Test::More tests => 2;
use Test::Exception;

use GDPR::IAB::TCFv2;

subtest "valid tcf v2 consent string" => sub {
    plan tests => 11;

    my $consent;

    lives_ok {
        $consent = GDPR::IAB::TCFv2->Parse('CLcVDxRMWfGmWAVAHCENAXCkAKDAADnAABRgA5mdfCKZuYJez-NQm0TBMYA4oCAAGQYIAAAAAAEAIAEgAA.argAC0gAAAAAAAAAAAA');
    } 'should not throw exception';

    isa_ok $consent, 'GDPR::IAB::TCFv2', 'gdpr iab tcf v2 consent';

    is $consent->version, 2, 'should return version 2';

    is $consent->created, 1228644257, 'should return the creation epoch 07/12/2008';

    is $consent->last_updated, 1326215413, 'should return the last update epoch 10/01/2012';

    is $consent->cmp_id, 21, 'should return the cmp id 21';
    
    is $consent->cmp_version, 7, 'should return the cmp version 7';

    is $consent->consent_screen, 2, 'should return the consent screen 2';

    is $consent->consent_language, "EN", 'should return the consent language "EN"';

    is $consent->vendor_list_version, 23, 'should return the vendor list version 23';

    subtest "check purpose ids" => sub {
        plan tests => 24;

        my %testcases =(
            1 => 1,
            3 => 1,
            9 => 1,
            10 => 1,
        );
        
        foreach my $id (1..24) {
            is !!$consent->is_purpose_allowed($id), !!$testcases{$id}, "checking purpose id $id";
        }
    }
};

subtest "invalid tcf consent string candidates" => sub {
    plan tests => 5;

    throws_ok {
        GDPR::IAB::TCFv2->Parse();
    } qr/missing gdpr consent string/, 'undefined consent string should throw error';

    throws_ok {
        GDPR::IAB::TCFv2->Parse("");
    } qr/missing gdpr consent string/, 'empty consent string should throw error';

    throws_ok {
        GDPR::IAB::TCFv2->Parse("BOEFEAyOEFEAyAHABDENAI4AAAB9vABAASA");
    } qr/consent string is not tcf version 2/, 
    'valid tcf v1 consent string should throw error (deprecated)';

    throws_ok {
        GDPR::IAB::TCFv2->Parse("Clc");
    } qr/vendor consent strings are at least 29 bytes long/, 
    'short (less than 29 bytes) tcf v2 consent string should throw error';

    throws_ok {
        GDPR::IAB::TCFv2->Parse("DOEFEAyOEFEAyAHABDENAI4AAAB9vABAASA");
    } qr/consent string is not tcf version 2/, 
    'possible tcf v3 consent string should throw error';
};