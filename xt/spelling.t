use strict;
use warnings;
use Test::More;

eval 'use Test::Spelling 0.12';
plan skip_all => 'Test::Spelling 0.12 required for testing POD spelling' if $@;

add_stopwords(<DATA>);
all_pod_files_spelling_ok();

__DATA__
TCF
TCFv1
TCFv2
TCString
IAB
CMP
CMPs
CMPVL
GDPR
GVL
DSP
SSP
DMP
adtech
JSON
YAML
CPAN
PAUSE
DockerHub
Linuxbrew
AUR
COPR
Peczenyj
Tiago
Weborama
metadata
namespace
namespaces
backend
frontend
deserialize
deserialized
serializer
parser
parsers
bitfield
bitfields
opt
runtime
v2
v3
