# Changelog

## v1.0.0
- Initial Release

## v1.0.1
- Fixed assert in the round function left over from pre-publication merge that caused processing to halt in debug builds
- Updates to README to clean up examples and provide more detailed instructions

## v1.0.2
- Updated CHANGELOG format
- Lowered swift toolchain requirements from 6.1 to 6.0 to support building with Swift 6.0
- Added support for watchOS by replacing some uses of Int with UInt32 or UInt64 (some watchOS versions specify 32-bit integers)
- Added explicit watchOs, tvOS and visionOS tags in the package manifest
- Removed README line describing hash verification (which was removed prior to initial publication, but came back in a merge)

## v1.0.3
- Refactored load64() utility function to ensure Swift 6.0 and 6.1 builds would not time out on type checking
- Bumped required version of tvOS from v13 to v18 to ensure availability of Mutex
- Updated README with tvOS version requirement change
