use strict;
use warnings;
use Benchmark qw(cmpthese);
use GDPR::IAB::TCFv2::BitField;

my $max_id = 10000;
my $data = '0' x $max_id;
for (1..5000) { substr($data, int(rand($max_id)), 1, '1') }

my $bf = bless {
    data => $data,
    max_id => $max_id,
    options => { json => { compact => 1 } }
}, 'GDPR::IAB::TCFv2::BitField';

cmpthese(1000, {
    original => sub {
        my @data = split //, $bf->{data};
        my $res = [ grep { $data[ $_ - 1 ] } 1 .. $bf->{max_id} ];
    },
    index_based => sub {
        my @ids;
        my $d = $bf->{data};
        my $pos = index($d, '1');
        while ($pos != -1 && $pos < $bf->{max_id}) {
            push @ids, $pos + 1;
            $pos = index($d, '1', $pos + 1);
        }
    }
});
