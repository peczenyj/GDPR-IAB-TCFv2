## [0.320] - 2026-05-05

### Other

- Centralized Quality Checks (xt/ & Makefile) 

## [0.310] - 2026-05-05

### Features

- Implement unified subcommand-based CLI and bump version to 0.310

## [0.300] - 2026-05-05

### Bug Fixes

- Fix yaml lint issues

### Other

- Independent iabtcf-dump CLI utility 
- Normalize macos
- Update changelog

## [0.203] - 2025-04-21

### Bug Fixes

- Fix tests with tap
- Fix perl tidy issue

### Other

- Update changelog
- Bump version to v0.203
- Try fix workflow linux last try
- Try fix workflow linux
- Try refactor linux tests
- Run perltidy on code
- Merge remote-tracking branch 'refs/remotes/origin/devel' into devel
- Update windows.yml

try fix windows
- Update linux.yml

install git and curl
- Update linux.yml

force install linux in older versions
- Update linux.yml

try fix images

## [0.202] - 2025-04-21

### Other

- Bump version
- Bump version
- Improve error message
- Update CONTRIBUTING.pod

fix branch again
- Update CONTRIBUTING.pod

fix branch again
- Merge tag 'v0.201' into devel

Tagged for release. v0.201

## [0.201] - 2023-12-20

### Other

- Merge branch 'release/0.201'
- Promote new version
- Bump version
- Change how we redefine subroutines
- Small fixes
- Merge tag 'v0.200' into devel

Tagged for release. v0.200

## [0.200] - 2023-12-17

### Bug Fixes

- Fix manifest
- Fix issue #25

### Other

- Merge branch 'release/0.200'
- Update manifest
- Promote new version
- Add missing changes
- Refactor publisher restrictions 

* add named parameters on check_publisher_restriction method

* add new method

* improve test

* Revert "improve test"

This reverts commit ae7274e49ad0b767b158beadd9ce73e07a5eb836.

* fix format

* fix pod

* Update Publisher.pm

Remove char

* Update PublisherRestrictions.pm

Remove char

* tidy test

* remove bad chars

* try remove all bad chars
- Increase tests
- Add range section cache 

* add initial code

* reorg code

* rename test

* add unit tests

* add pod

* update readme
- Merge tag 'v0.100' into devel

Tagged for release. v0.100

## [0.100] - 2023-12-15

### Bug Fixes

- Fix workflows

### Other

- Merge branch 'release/0.100'
- Tidy file
- Update manifest
- Promote new version
- Remove unused code
- Add support to publisher tc 

* add code to handle publisher tc, start to implement #13

* add missing changes

* some refactor

* add example

* update pod

* add unit tests

* add unit tests

* force read the first segment as core string

* verify unit tests

* narrow unit test

* narrow unit test 2

* continue search

* fix unit test
- Prepare code to decode other sections
- Fetch other sections of the tcstring
- Group publisher section
- Group constants
- Add strict mode
- Merge tag 'v0.084' into devel

Tagged for release. v0.084

### Refactor

- Refactor code, regroup logic
- Refactor code: group vendor section

## [0.084] - 2023-12-14

### Other

- Merge branch 'release/0.084'
- Update manifest
- Promote new version
- Bump version
- Fix but index out of bonds while parsing range based consent strings 

* add unit test to trigger bug #20 

* add fix

* add changes file
- Merge tag 'vv0.083' into devel

Tagged for release. vv0.083

## [0.083] - 2023-12-13

### Bug Fixes

- Fix pod 2
- Fix pod
- Fix changes

### Other

- Merge branch 'release/v0.083'
- Update manifest
- Bump version
- Revert "try fix links"

This reverts commit e5fb435f3d78beb07ef44b434282724c4f0270ec.
- Revert "try 2"

This reverts commit dca6f2f25344bbd226f8ef79780414f57b378f1a.
- Try 2
- Try fix links
- Merge branch 'devel' of github.com:peczenyj/GDPR-IAB-TCFv2 into devel
- Refactor bitfield & others 

* increase performance in 17% on TO_JSON method when it is bitfield by limit data size

* small refactor on range section

* continue refactor on bitfield, range section and publisher restriction

* refactor offsets

* add changes

* refactor offset / data_size

* verify if offset exists on range section Parse method

* fix tidy

* restrict bitfield data

* tidy code
- Restrict bitfield data
- Reset readme
- Merge branch 'devel' of github.com:peczenyj/GDPR-IAB-TCFv2 into devel
- Update README.pod

Try fix link to method
- Format changes
- Increase performance on range section 

performance improvement on range objects

## [0.082] - 2023-12-12

### Bug Fixes

- Fix perltidy
- Fix example in pod
- Fix pod
- Fix issue #17
- Fix pod
- Fix typo in exception, add more bit check
- Fix pod json fields
- Fix format

### Other

- Bump version to 0.082
- Update changes
- Add small refactor on safe functions
- Revert "refactor purposes and special feature opt in internals"

This reverts commit af62cf3873f673bcc0f790a2523a036042ec34d6.
- Rename options
- Start refactor
- Remove useless method
- Update changes
- Update changes
- Increase TO_JSON performance by 17% on bitfields and 70% on range based
- Add new tests
- Update changelog
- Rename property
- Change bitutils to return the offset of the next piece of information
- Improve bitutils to also return next offset in array context via wantarray

### Refactor

- Refactor purposes and special feature opt in internals

## [0.081] - 2023-12-11

### Bug Fixes

- Fix pod

### Other

- Bump version
- Start to fix issue #17

## [0.08] - 2023-12-10

### Bug Fixes

- Fix makefile
- Fix typo
- Fix pod and readme

### Other

- Update manifest
- Bump version
- Finish TO_JSON method
- Add tests and small refactors in code
- Add missing changes
- Add TO_JSON and tc_string method
- Add TO_JSON method
- Remove = character from base64 validation, since the url version does not have it
- Substitute hardcoded numeric offsets by constants
- Update issue templates
- Create CODE_OF_CONDUCT.md

add coc
- Add missing function on perldoc
- Update TCFv2.pm

add badges
- Update README.pod

add new bagdes
- Update perlcritic.yml

retry perlcritic
- Update perlcritic.yml

try different approach
- Update perlcritic.yml

try again
- Create perlcritic.yml
- Update TCFv2.pm

update badges
- Delete .appveyor.yml

remove appveyor
- Update README.pod

update badges
- Rename macos.yaml to macos.yml

rename file
- Update linux.yml

fix 2
- Update linux.yml

fix linux
- Update linux.yml

improve linux tests
- Create macos.yaml

add tests on macos
- Create windows.yml

add tests on windows
- Create perltidy.yml

add perldity
- Update TCFv2.pm

fix typo in badges
- Update README.pod

fix pod
- Update README.pod

fix typo
- Update linux.yml

try fix git config
- Update linux.yml

add coveralls repo token on secret
- Update linux.yml
- Update linux.yml

update action
- Add test pod and fix small typos
- Explain changes
- Add version on changes file

## [0.07] - 2023-12-07

### Bug Fixes

- Fix unit tests again
- Fix unit test
- Fix type validation
- Fix pod

### Other

- Simplify code
- Remove usage of // operation
- Revert "fix unit test"

This reverts commit c56400f41b1f71f516d999786ec88f1144945f48.
- Update manifest
- Bump version
- Merge branch 'main' of github.com:peczenyj/GDPR-IAB-TCFv2
- Update TCFv2.pm

Fix pod
- Update README.pod

Fix pod
- Update changelog
- Update readme
- Add publisher restriction check and fix issue #11
- Check if string is a base64 url encoded string before parse it and fix issue #3

## [0.06] - 2023-12-06

### Other

- Update docs
- Bump version to 0.06
- Update changes
- Add wantarray on created and last_updated methods
- Add coveralls badge
- Update linux.yml

add coveralls
- Add badge
- Add appveyor
- Push new constants and docs
- Merge branch 'main' of github.com:peczenyj/GDPR-IAB-TCFv2
- Update linux.yml

rename
- Add new readme
- Update readme
- Add special features as constants
- Add purposes constants, fix issue #2
- Simplify ctor
- Add comments
- Add small changes in code

## [0.051] - 2023-12-05

### Bug Fixes

- Fix readme
- Fix readme
- Fix branch name
- Fix pod
- Fix contributing file

### Other

- Release version 0.051

## [0.05] - 2023-12-05

### Other

- Add missing changes

## [0.0.5] - 2023-12-05

### Bug Fixes

- Fix module format
- Fix test matrix
- Fix manifest
- Fix issue #9 by trying to use MIME::Base64->can("decode_base64url")  or use a fallback

### Other

- Bump version
- Try to force mininum perl 5.8
- Try make it work on perl 5.8
- Try even older version
- Try again
- Small refactors
- Try fix markdown format

## [0.0.4] - 2023-12-04

### Bug Fixes

- Fix issue #8
- Fix dependency

### Other

- Add manifest
- Add contributing file
- Add changelog
- Update version

## [0.0.3] - 2023-12-04

### Other

- Add manifest
- Improve doc
- Complete pod documentation
- Add full support to vendor consent and vendor legitimate interest, ias bitfield or range sections. fix issue #1
- Complete code, add support to bitfields
- Add more methods

## [0.0.2] - 2023-12-03

### Other

- Update code, add skip
- Rename readme
- Improve documentation
- Skip .github dir
- Update license
- Add github meta

## [0.0.1] - 2023-12-02

### Other

- Add github workflow
- Add makefile.pl
- Add *.bak on .gitignore
- Remove .bak
- Add some properties and tests
- Initial commit

<!-- generated by git-cliff -->
