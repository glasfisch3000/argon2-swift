@inlinable
func uint32FromBytes(_ bytes: [UInt8]) -> UInt32 {
    assert(bytes.count == 4, "Incorrect number of bytes for UInt32")
    return UInt32(bytes[0]) |
           UInt32(bytes[1]) << 8 |
           UInt32(bytes[2]) << 16 |
           UInt32(bytes[3]) << 24
}

@inlinable
func uint64FromBytes(_ bytes: [UInt8]) -> UInt64 {
    assert(bytes.count == 8, "Incorrect number of bytes for UInt64")
    return UInt64(bytes[0]) |
           UInt64(bytes[1]) << 8 |
           UInt64(bytes[2]) << 16 |
           UInt64(bytes[3]) << 24 |
           UInt64(bytes[4]) << 32 |
           UInt64(bytes[5]) << 40 |
           UInt64(bytes[6]) << 48 |
           UInt64(bytes[7]) << 56
}

@inlinable
func bytesFromUInt64(_ value: UInt64) -> [UInt8] {
    return [
        UInt8(value & 0xFF),
        UInt8((value >> 8)  & 0xFF),
        UInt8((value >> 16) & 0xFF),
        UInt8((value >> 24) & 0xFF),
        UInt8((value >> 32) & 0xFF),
        UInt8((value >> 40) & 0xFF),
        UInt8((value >> 48) & 0xFF),
        UInt8((value >> 56) & 0xFF)
    ]
}

@inlinable
func rotateRight(_ value: UInt64, by amount: Int) -> UInt64 {
    return (value >> amount) | (value << (64 - amount))
}

/// Masks off the least-significant 32-bits of a 64-bit unsigned integer
@inlinable
func trunc(_ v: UInt64) -> UInt64 {
    return v & 0x00000000FFFFFFFF
}

@inlinable
func load64(_ src: [UInt8], i: Int) -> UInt64 {
    let b0 = UInt64(src[i + 0])
    let b1 = UInt64(src[i + 1])
    let b2 = UInt64(src[i + 2])
    let b3 = UInt64(src[i + 3])
    let b4 = UInt64(src[i + 4])
    let b5 = UInt64(src[i + 5])
    let b6 = UInt64(src[i + 6])
    let b7 = UInt64(src[i + 7])
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24) | (b4 << 32) | (b5 << 40) | (b6 << 48) | (b7 << 56)
}
