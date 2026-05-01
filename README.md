## SwiftArgon2
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Pure Swift 6 (memory-safe, zero dependency, structured concurrency) implementation of [Argon2], the winner of the [Password Hash Competition].
                 
Includes a slimmed-down Swift 6 (memory-safe) implementation of Blake2b that only implements the operations needed for Argon2.
                 
Not as fast as the C reference implementation (about 2x-3x slower), but easy to use and performant enough for many use cases without requiring any unsafe memory operations.
                 
This library is primarily intended to be used as a PBKDF on mobile devices, and *not* as a server-side password hashing verifier.
                 
PLEASE NOTE: This has only been testing on Little-Endian systems and may not work on Big-Endian CPUs.

ALSO NOTE: We do make one compromise to memory-safety, which is to securely wipe data after computation with unsafe calls to memset_s().  If you want a purely memory-safe version that does not wipe the data, remove the MIMICLONE_SECURE_WIPE compiler flag when building

## Installation (SPM)

SwiftArgon2 can be installed via SPM (Swift Package Manger) by adding the following to your depencencies:

```swift
.package(url: "https://github.com/mimiclone/argon2-swift.git", .branch("main"))
```

## Usage

High-level hashing of a password

```swift
import SwiftArgon2

// Create the instance
let argon2 = Argon2(
    params: .init(
        parallelism: 4,     // Number of lanes (threads)
        tagLength: 32,      // Output length (in bytes)
        memorySize: 32,     // Memory size (in KiB)
        iterations: 3,      // Number of passes
        variant: .argon2d   // Variant: (.argon2d, .argon2i, .argon2id)
    )
)
                 
// Compute the hash
let hashData = try? await argon2.compute(
    password: "PasswordToHash".data(using: .utf8)!,
    salt: "Use a cryptographically secure salt".data(using: .utf8)!
    // Optional secret
    // Optional associated data
)
```

## Features and bugs

Please file feature requests and bugs at the [issue tracker].

[issue tracker]: https://github.com/mimiclone/argon2-swift/issues

## Licensing

- SwiftArgon2 is Licensed under the [MIT License]

[Argon2]: https://github.com/P-H-C/phc-winner-argon2
                 
[Password Hash Competition]: https://password-hashing.net
                 
[MIT License]: https://github.com/mimiclone/argon2-swift/blob/main/LICENSE
