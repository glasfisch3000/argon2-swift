import struct Foundation.Data

enum Blake2Error: Error {
    case incorrectKeySize
    case incorrectParameterSize
}

/**
 A slimmed-down implementation of Blake2b intended only for use by Argon2.  Supports only single-call finalized hashing from within
 the package, and does not expose anything at all to users of the package.  Does not make use of any unsafe memory access.
 */
struct Blake2b: Sendable {

    @usableFromInline
    struct State: Sendable {
        
        @usableFromInline
        var buffer: [UInt8]
        
        @usableFromInline
        var chainingValue: [UInt64]
        
        @usableFromInline
        var offsetCounter: [UInt64]
        
        @usableFromInline
        var finalizationFlag: [UInt64]
        
        @usableFromInline
        var compressionState: Int
        
        @usableFromInline
        var digestLength: Int

        @usableFromInline
        init() {
            self.buffer             = .init(repeating: 0, count: 128)
            self.chainingValue      = .init(repeating: 0, count: 8)
            self.offsetCounter      = .init(repeating: 0, count: 2)
            self.finalizationFlag   = .init(repeating: 0, count: 2)
            self.compressionState   = 0
            self.digestLength       = 0
        }
    }

    @usableFromInline
    static let parameterBlock: [UInt8] = Array(repeating: 0, count: 64)

    @usableFromInline
    static let iv: [UInt64] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ]

    @usableFromInline
    static let sigma: [[UInt8]] = [
        [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
        [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
        [ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ],
        [  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ],
        [  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 ],
        [  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 ],
        [ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 ],
        [ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 ],
        [  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 ],
        [ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 ],
        [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
        [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ]
    ]

    @usableFromInline
    var state: State!

    static func hash(digestLength: Int, data: Data) throws -> Data {
        var hasher = try Blake2b(digestLength: digestLength)
        hasher.update(data: data)
        return hasher.finalize()
    }
    
    @inlinable
    init(digestLength: Int = 64) throws {
        
        // Digest Length
        guard digestLength != 0 && digestLength <= 64 else {
            throw Blake2Error.incorrectParameterSize
        }

        // Context
        var ctx             = State()
        ctx.digestLength    = digestLength
        
        // Parameter Block
        var parameterBlock  = Self.parameterBlock
        parameterBlock[0]   = UInt8(digestLength)
        parameterBlock[2]   = 1 // fanout
        parameterBlock[3]   = 1 // depth

        // Init hash state
        for i in 0..<8 {
            ctx.chainingValue[i] = Self.iv[i] ^
                load64(parameterBlock, i: i * MemoryLayout<UInt64>.size)
        }

        self.state = ctx
    }

    @inlinable
    mutating func incrementCounter(by inc: UInt64) {
        self.state.offsetCounter[0] += inc
        self.state.offsetCounter[1] += self.state.offsetCounter[0] < inc ? 1 : 0
    }

    @inlinable
    mutating func compress() {
        
        @inline(__always)
        func g(
            _ r: Int, _ i: Int,
            _ a: Int, _ b: Int, _ c: Int, _ d: Int
        ) {
            v[a] = v[a] &+ v[b] &+ m[Int(Blake2b.sigma[r][2 * i + 0])]
            v[d] = rotateRight(v[d] ^ v[a], by: 32)
            v[c] = v[c] &+ v[d]
            v[b] = rotateRight(v[b] ^ v[c], by: 24)
            v[a] = v[a] &+ v[b] &+ m[Int(Blake2b.sigma[r][2 * i + 1])]
            v[d] = rotateRight(v[d] ^ v[a], by: 16)
            v[c] = v[c] &+ v[d]
            v[b] = rotateRight(v[b] ^ v[c], by: 63)
        }
        
        @inline(__always)
        func round(_ r: Int) {
            g(r, 0, 0, 4,  8, 12)
            g(r, 1, 1, 5,  9, 13)
            g(r, 2, 2, 6, 10, 14)
            g(r, 3, 3, 7, 11, 15)
            g(r, 4, 0, 5, 10, 15)
            g(r, 5, 1, 6, 11, 12)
            g(r, 6, 2, 7,  8, 13)
            g(r, 7, 3, 4,  9, 14)
        }
        
        var m = [UInt64](repeating: 0, count: 16)
        var v = [UInt64](repeating: 0, count: 16)

        for i in 0..<16 {
            m[i] = load64(self.state.buffer, i: i * MemoryLayout<UInt64>.size)
        }

        for i in 0..<8 {
            v[i] = self.state.chainingValue[i]
        }

        v[8] =  Self.iv[0]
        v[9] =  Self.iv[1]
        v[10] = Self.iv[2]
        v[11] = Self.iv[3]
        v[12] = Self.iv[4] ^ self.state.offsetCounter[0]
        v[13] = Self.iv[5] ^ self.state.offsetCounter[1]
        v[14] = Self.iv[6] ^ self.state.finalizationFlag[0]
        v[15] = Self.iv[7] ^ self.state.finalizationFlag[1]

        for i in 0..<12 {
            round( i)
        }

        for i in 0..<8 {
            self.state.chainingValue[i] = self.state.chainingValue[i] ^ v[i] ^ v[i + 8]
        }
        
    }

    @inlinable
    mutating func update(data: Data) {
        for i in data.indices {
            if self.state.compressionState == 128 {
                self.incrementCounter(by: UInt64(128))
                self.compress()
                self.state.compressionState = 0
            }
            self.state.buffer[self.state.compressionState] = data[i]
            self.state.compressionState += 1
        }
    }
    
    private mutating func finalize() -> Data {
        
        // Increment counter
        self.incrementCounter(by: UInt64(self.state.compressionState))
        
        while self.state.compressionState < 128 {
            self.state.buffer[self.state.compressionState] = 0
            self.state.compressionState += 1
        }
        
        self.state.finalizationFlag[0] = UInt64.max
        self.compress()
        
        var result = Data(repeating: 0, count: self.state.digestLength)
        for i in 0..<self.state.digestLength {
            result[i] = UInt8((self.state.chainingValue[i >> 3] >> (8 * (i & 7))) & 0xFF)
        }
        
        return result
    }
    
}
