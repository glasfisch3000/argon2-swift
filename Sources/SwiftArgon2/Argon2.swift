import struct Foundation.Data
import struct Synchronization.Mutex

/// The variant of Argon2 to use
public enum Argon2Variant: Sendable {
    
    /**
     * Data-dependent addressing.  Faster but more vulnerable to side-channel attacks
     */
    case argon2d
    
    /**
     * Data-independent addressing.  Slower but more resistant to side-channel attacks
     */
    case argon2i
    
    /**
     * Hybrid approach.  First half data-independent, second half data-dependent
     */
    case argon2id
    
    /**
     * UInt32 value used for building the H0 parameter block
     */
    var intValue: UInt32 {
        switch self {
        case .argon2d: return 0
        case .argon2i: return 1
        case .argon2id: return 2
        }
    }
    
    /**
     * Name used for encoded hash output
     */
    var name: String {
        switch self {
        case .argon2d: return "argon2d"
        case .argon2i: return "argon2i"
        case .argon2id: return "argon2id"
        }
    }
}

public struct Argon2Params : Sendable {
    
    let parallelism: UInt32
    let tagLength: UInt32
    let memorySize: UInt32
    let iterations: UInt32
    let variant: Argon2Variant
    let version: UInt32 = 0x13 // 19 encoded as hex
    
    public init(
        parallelism: UInt32? = nil,
        tagLength: UInt32? = nil,
        memorySize: UInt32? = nil,
        iterations: UInt32? = nil,
        variant: Argon2Variant? = nil
    ) {
        self.parallelism = parallelism ?? 4
        self.tagLength = tagLength ?? 32
        self.memorySize = memorySize ?? 65536
        self.iterations = iterations ?? 3
        self.variant = variant ?? .argon2id
    }
    
}

public enum Argon2Error: Error {
    case invalidPasswordLength
    case invalidSaltLength
    case invalidParameters
    case blake2bFailed
}

/// SwiftArgon2: A class that implements the Argon2 password hashing algorithm
public struct Argon2 : Sendable {
    
    // MARK: - Constants
    
    // Password constants
    private static let minimumPasswordBytes: Int = 0
    private static let maximumPasswordBytes: Int = 4294967295 // UInt32.max = 2^32-1
    private static let passwordInputRange = Argon2.minimumPasswordBytes...Argon2.maximumPasswordBytes
    
    // Salt constants
    private static let minimumSaltBytes: Int = 8
    private static let maximumSaltBytes: Int = 4294967295 // UInt32.max = 2^32-1
    private static let saltInputRange = Argon2.minimumSaltBytes...Argon2.maximumSaltBytes
    
    // Parallelism constants
    private static let minParallelism: UInt32 = 1
    private static let maxParallelism: UInt32 = 16777215 // 2^24-1
    private static let parallelismRange = Argon2.minParallelism...Argon2.maxParallelism
    
    // Tag Length constants
    private static let minTagBytes: UInt32 = 4
    private static let maxTagBytes: UInt32 = 4294967295 // UInt32.max = 2^32-1
    private static let tagLengthInputRange = Argon2.minTagBytes...Argon2.maxTagBytes
    
    // Memory Size constants
    private static let maxMemoryKibibytes: UInt32 = 4294967295 // UInt32.max = 2^32-1
    
    // Time Cost (Iterations) constants
    private static let minIterations: UInt32 = 1
    private static let maxIterations: UInt32 = 4294967295 // 2^32-1
    private static let iterationsRange = Argon2.minIterations...Argon2.maxIterations
    
    // MARK: - Internal Types
    
    struct Block {
        
        var v: [UInt64] = [UInt64](repeating: 0, count: 128)
        
        mutating func fill(_ data: Data) {
            precondition(data.count == 1024, "Attempted to fill block with \(data.count) bytes, expected 1024")
            var updatedBlock: [UInt64] = .init(repeating: 0, count: 128)
            for index in 0..<128 {
                let dataStartIndex = index * 8
                updatedBlock[index] = uint64FromBytes(Array(data[dataStartIndex..<dataStartIndex+8]))
            }
            v = updatedBlock
        }
        
        mutating func xorIntoSelf(_ other: Block) {
            v = zip(v, other.v).map { $0 ^ $1 }
        }
        
        mutating func secureWipe() {
            v.secureWipe()
        }
        
        func copy() -> Block {
            return Block(v: v.map { $0 })
        }
        
        func bytes() -> Data {
            return v.map { bytesFromUInt64($0) }.reduce(Data()) { $0 + $1 }
        }
        
    }
    
    struct Context: Sendable {
        
        var password:       Data
        var salt:           Data
        var secret:         Data
        var associatedData: Data
        
        var memory: [Block]
    
        let numBlocks: Int
        let numLanes: Int
        
        let laneLength: Int
        let segmentLength: Int
        
        init(
            _ params:           Argon2Params,
            _ password:         Data,
            _ salt:             Data,
            _ secret:           Data? = nil,
            _ associatedData:   Data? = nil
        ) {
            
            // Store specifics of invocation
            self.password       = password
            self.salt           = salt
            self.secret         = secret            ?? Data()
            self.associatedData = associatedData    ?? Data()
            
            // Calculate memory storage dimensions (a block is 128 UInt64 values = 1024 bytes)
            let memoryAlignment = UInt64(4) * UInt64(params.parallelism)
            numBlocks = Int(UInt64(params.memorySize) / memoryAlignment * memoryAlignment)
            numLanes = Int(params.parallelism)
            laneLength = numBlocks / numLanes
            segmentLength = laneLength / 4
            
            // Allocate memory
            memory = [Block](repeating: Block(), count: numBlocks)
            
        }
        
        mutating func secureWipe() {
            password.secureWipe()
            salt.secureWipe()
            secret.secureWipe()
            associatedData.secureWipe()
            for i in 0..<memory.count {
                memory[i].secureWipe()
            }
        }
        
    }

    struct Position: Sendable {
        let pass: Int
        let lane: Int
        let slice: Int
        var index: Int
    }
    
    struct SegmentResult: Sendable {
        let startIndex: Int
        let segmentBlocks: [Block]
    }
    
    // MARK: - Properties
    
    private let params: Argon2Params
    
    // MARK: - Initialization
    
    /// Initialize the Argon2 instance
    public init(params: Argon2Params) throws {
        
        // GUARD: Parallelism (p -> number of lanes)
        guard Argon2.parallelismRange.contains(params.parallelism) else {
            throw Argon2Error.invalidParameters
        }
        
        // GUARD: Tag Length (T -> number of bytes)
        guard Argon2.tagLengthInputRange.contains(params.tagLength) else {
            throw Argon2Error.invalidParameters
        }
        
        // GUARD: Memory Size (m -> number of kilobyte blocks)
        let minMemorySize: UInt32 = 8 * params.parallelism
        let memorySizeRange = (minMemorySize...Argon2.maxMemoryKibibytes)
        guard memorySizeRange.contains(params.memorySize) else {
            throw Argon2Error.invalidParameters
        }
        
        // GUARD: Iterations (t -> number of passes)
        guard Argon2.iterationsRange.contains(params.iterations) else {
            throw Argon2Error.invalidParameters
        }
        
        self.params = params
        
    }
    
    // MARK: - Public Methods
    
    public func computeEncoded(
        password: Data,
        salt: Data,
        secret: Data? = nil,
        associatedData: Data? = nil
    ) async throws -> String {
        
        // Perform the hash
        let hashData = try await compute(password: password, salt: salt, secret: secret, associatedData: associatedData)
        
        var encodedHash = "$\(params.variant.name)"
        encodedHash.append("$v=\(params.version)")
        encodedHash.append("$m=\(params.memorySize)")
        encodedHash.append(",t=\(params.iterations)")
        encodedHash.append(",p=\(params.parallelism)")
        encodedHash.append("$")
        encodedHash.append(salt.argon2B64String())
        encodedHash.append("$")
        encodedHash.append(hashData.argon2B64String())
        
        return encodedHash
        
    }
    
    /// Run Argon2 algorithm
    /// - Parameters:
    ///   - password: The password to hash
    ///   - salt: The salt to use (should be at least 8 bytes)
    ///   - secret: Optional secret material to include
    ///   - associatedData: Optional associated data to include
    /// - Returns: The computed hash as Data
    /// - Throws: Error if hashing fails
    public func compute(
        password: Data,
        salt: Data,
        secret: Data? = nil,
        associatedData: Data? = nil
    ) async throws -> Data {
        
        // Create context
        var context = try createContext(password: password, salt: salt, secret: secret, associatedData: associatedData)
        
        defer { context.secureWipe() }
        
        // Calculate the pre-hash digest (H0)
        let h0: Data = try preHashDigest(context)
        
        // Fill initial blocks
        fillFirstBlocks(&context, h0)
        
        // Repeat for number of passes
        for pass in 0..<Int(params.iterations) {
            
            // Compute slice-wise
            for sliceIndex in 0...3 {
                
                // Write-only mutex
                let lock = Mutex<Void>(())
                
                await withTaskGroup(of: SegmentResult.self) { group in
                    
                    // Compute each lane
                    for lane: Int in 0..<context.numLanes {
                        
                        let position = Position(pass: pass, lane: lane, slice: sliceIndex, index: 0)
                        
                        // Add task to group
                        group.addTask { [context, position] in
                            
                            // Calculate blocks for the segment
                            return fillSegment(context, position)
                            
                        }
                        
                        // Update memory with segment results
                        for await segmentResult in group {
                            // Update the memory
                            lock.withLock { _ in
                                context.memory.replaceSubrange(
                                    segmentResult.startIndex..<(segmentResult.startIndex + segmentResult.segmentBlocks.count),
                                    with: segmentResult.segmentBlocks
                                )
                            }
                        }
                        
                    }
                    
                    // Wait for all segments in the lane to complete
                    await group.waitForAll()
                    
                }
                
            }
            
        }
        
        // Compute final block
        return finalize(&context)
        
    }
    
    // MARK: - Private Methods
    
    private func createContext(password: Data, salt: Data, secret: Data?, associatedData: Data?) throws -> Context {
        
        // GUARD: Password (P) length
        guard Argon2.passwordInputRange.contains(password.count) else {
            throw Argon2Error.invalidPasswordLength
        }
        
        // GUARD: Salt (S) Length
        guard Argon2.saltInputRange.contains(salt.count) else {
            throw Argon2Error.invalidSaltLength
        }
        
        return Context(params, password, salt, secret, associatedData)
        
    }
    
    private func preHashDigest(_ context: Context) throws -> Data {
        
        // Precompute total size of the param block so we don't reallocate on append
        let totalSize = 6*4 + 4 + context.password.count + 4 + context.salt.count +
        4 + context.secret.count + 4 + context.associatedData.count
        
        // Create the parameter block to feed into the hashing algorithm
        var paramBlock = Data(capacity: totalSize)
        
        // Make sure this is securely wiped after computation
        defer { paramBlock.secureWipe() }
        
        // Add parameter blocks
        paramBlock += params.parallelism.littleEndian.data
        paramBlock += params.tagLength.littleEndian.data
        paramBlock += params.memorySize.littleEndian.data
        paramBlock += params.iterations.littleEndian.data
        paramBlock += params.version.littleEndian.data
        paramBlock += params.variant.intValue.littleEndian.data
        
        // Append password to paramater block
        paramBlock += UInt32(context.password.count).littleEndian.data
        paramBlock += context.password
        
        // Append salt to parameter block
        paramBlock += UInt32(context.salt.count).littleEndian.data
        paramBlock += context.salt
        
        // Append secret length and content (always, even if empty)
        paramBlock += UInt32(context.secret.count).littleEndian.data
        paramBlock += context.secret

        // Append associated data length and content (always, even if empty)
        paramBlock += UInt32(context.associatedData.count).littleEndian.data
        paramBlock += context.associatedData
        
        // If all required inputs are filled, with a password of length 0 and a salt of length 8, the paramBlock will be 48 bytes
        precondition(paramBlock.count >= 48, "Parameter block is too short")
        
        // Establish H0
        return try digest(64, paramBlock)
        
    }
    
    /**
     Fills the first two blocks (index 0 and 1) in each lane of the block memory
     */
    private func fillFirstBlocks(_ context: inout Context, _ blockHash: Data) {
        
        for lane in 0..<context.numLanes {
            
            // Fill first block in lane
            let firstBlockIndex = context.laneLength * lane
            let firstBlockData = blockHash + UInt32(0).littleEndian.data + UInt32(lane).littleEndian.data
            context.memory[firstBlockIndex].fill(extendedDigest(1024, firstBlockData))
            
            // Fill second block in lane
            let secondBlockIndex = firstBlockIndex + 1
            let secondBlockData = blockHash + UInt32(1).littleEndian.data + UInt32(lane).littleEndian.data
            context.memory[secondBlockIndex].fill(extendedDigest(1024, secondBlockData))
            
        }
        
    }
    
    /**
     Fills a segment
     */
    private func fillSegment(_ context: Context, _ position: Position) -> SegmentResult {
        
        // Declare result
        var result: [Block] = []
        
        // Initialize blocks
        let zeroBlock = Block()
        var inputBlock = Block()
        var addressBlock = Block()
        
        // Determine if we need to calculate data independent reference block indices
        // Argon2d -> Does not pre-calculate indices
        // Argon2i -> Calculate block indexes for every segment on every pass
        // Argon2id -> Calculate block indexes on the first pass for the first two segments
        let dataIndependentAddressing = (
            params.variant == .argon2i ||
            ( params.variant == .argon2id && position.pass == 0 && position.slice < 2 )
        )
        
        if dataIndependentAddressing {
            
            // NOTE: The reference implementation fills the zero block and input block with all 0s.
            //       that is not necessary in Swift since it guarantees initialized memory
            
            inputBlock.v[0] = UInt64(position.pass)
            inputBlock.v[1] = UInt64(position.lane)
            inputBlock.v[2] = UInt64(position.slice)
            inputBlock.v[3] = UInt64(context.numBlocks)
            inputBlock.v[4] = UInt64(params.iterations)
            inputBlock.v[5] = UInt64(params.variant.intValue)
        }
        
        // Declare tracking indices
        var prevBlockIndex: Int
        var currBlockIndex: Int
        var startingIndex: Int
        
        startingIndex = 0
        
        // If this is the first pass of the first slice
        if position.pass == 0 && position.slice == 0 {
            
            // We have already generated the first two blocks in the segment
            startingIndex = 2
            
            // Generate the next set of addresses depending on mode
            if dataIndependentAddressing {
                nextAddresses(&addressBlock, &inputBlock, zeroBlock)
            }
            
        }
        
        // Calculate the index of the current block in the memory array
        currBlockIndex = position.lane * context.laneLength + position.slice * context.segmentLength + startingIndex
        
        // Calculate the index of the previous block in the memory array
        if currBlockIndex % context.laneLength == 0 {
            
            // If the current block is the first block in the lane, the "previous" block is the last block in the lane
            prevBlockIndex = currBlockIndex + context.laneLength - 1
            
        } else {
            
            // Otherwise the "previous" block is the block directly preceding the current block
            prevBlockIndex = currBlockIndex - 1
            
        }
        
        // Declare values for reference block tracking
        var pseudoRand: UInt64
        var refLane: Int
        var refIndex: Int
        
        // Make a mutable copy of the position
        var pos = position
        
        var segmentBlockMap: [Int: Int] = [:]
        
        // Iterate over the remaining blocks in the segment
        for index in startingIndex..<context.segmentLength {
            
            // Rotate prevBlockIndex if needed
            // NOTE: This check is required because the startingIndex may be 0 or 2, depending on the pass
            if currBlockIndex % context.laneLength == 1 {
                prevBlockIndex = currBlockIndex - 1
            }
            
            if dataIndependentAddressing {
                
                // If we have used all the addresses in the address block
                if index % 128 == 0 {
                    
                    // Fill the address block with fresh addresses
                    nextAddresses(&addressBlock, &inputBlock, zeroBlock)
                    
                }
                
                // Retrieve the pseudo random number from the address block
                pseudoRand = addressBlock.v[index % 128]
                
            } else {
                
                // Retrieve the pseudo random number from the previous block
                if let prevBlockSegmentIndex = segmentBlockMap[prevBlockIndex] {
                    pseudoRand = result[prevBlockSegmentIndex].v[0]
                } else {
                    pseudoRand = context.memory[prevBlockIndex].v[0]
                }
                
            }
            
            // Calculate the reference block lane
            refLane = Int((pseudoRand >> 32) % UInt64(context.numLanes))
            
            // Cannot reference other lanes in the first slice of the first pass
            if pos.pass == 0 && pos.slice == 0 {
                refLane = pos.lane
            }
            
            // Compute the number of possible reference blocks within the lane
            pos.index = index
            
            refIndex = indexAlpha(context, pos, UInt32(trunc(pseudoRand)), refLane == pos.lane)
            
            // Retrieve the reference block
            let refBlockIndex = context.laneLength * refLane + refIndex
            var refBlock: Block
            if let refBlockSegmentIndex = segmentBlockMap[refBlockIndex] {
                refBlock = result[refBlockSegmentIndex]
            } else {
                refBlock = context.memory[refBlockIndex]
            }
            
            // Retrieve the previous block
            var prevBlock: Block
            if let prevBlockSegmentIndex = segmentBlockMap[prevBlockIndex] {
                prevBlock = result[prevBlockSegmentIndex]
            } else {
                prevBlock = context.memory[prevBlockIndex]
            }
            
            // Calculate the next block
            if pos.pass == 0 {
                // First Pass
                segmentBlockMap[currBlockIndex] = result.count
                result.append(compress(prevBlock, refBlock))
            } else {
                // Subsequent passes
                segmentBlockMap[currBlockIndex] = result.count
                result.append(compress(prevBlock, refBlock, context.memory[currBlockIndex]))
            }
            
            // Increment the current and previous block indices
            currBlockIndex += 1
            prevBlockIndex += 1
            
        }
        
        return SegmentResult(
            startIndex: position.lane * context.laneLength + position.slice * context.segmentLength + startingIndex,
            segmentBlocks: result
        )
        
    }
    
    /**
     Fills the address block with the next 128 UInt64 values generated pseudo-randomly with the compression function
     */
    private func nextAddresses(_ addressBlock: inout Block, _ inputBlock: inout Block, _ zeroBlock: Block) {
        
        // Increment the counter
        inputBlock.v[6] += 1
        
        // Replace address block
        addressBlock = compress( zeroBlock, compress(zeroBlock, inputBlock))
        
    }
    
    private func indexAlpha(_ context: Context, _ pos: Position, _ pseudoRand: UInt32, _ sameLane: Bool) -> Int {
        
        var referenceAreaSize: UInt32
        var relativePosition: UInt64
        var startPosition: UInt32
        var absolutePosition: UInt32
        
        if pos.pass == 0 {
            
            // First Pass
            if pos.slice == 0 {
                
                // First Slice
                referenceAreaSize = UInt32(pos.index - 1)
                
            } else {
                
                if sameLane {
                    referenceAreaSize = UInt32(pos.slice * context.segmentLength + pos.index - 1)
                } else {
                    referenceAreaSize = UInt32(pos.slice * context.segmentLength + (pos.index == 0 ? -1 : 0))
                }
                
            }
            
        } else {
            
            // Additional passes
            if sameLane {
                referenceAreaSize = UInt32(context.laneLength - context.segmentLength + pos.index - 1)
            } else {
                referenceAreaSize = UInt32(context.laneLength - context.segmentLength + (pos.index == 0 ? -1 : 0))
            }
            
        }
        
        relativePosition = UInt64(pseudoRand)
        relativePosition = (relativePosition * relativePosition) >> 32
        let offset = (UInt64(referenceAreaSize) * relativePosition) >> 32
        relativePosition = UInt64(referenceAreaSize - 1) - offset
        
        startPosition = 0
        if pos.pass != 0 {
            startPosition = pos.slice == 3 ? UInt32(0) : (UInt32(pos.slice) + 1) * UInt32(context.segmentLength)
        }
        
        absolutePosition = (startPosition + UInt32(relativePosition)) % UInt32(context.laneLength)
        
        
        return Int(absolutePosition)
        
    }
    
    private func finalize(_ context: inout Context) -> Data {
        
        // Retrieve the very last block in the first lane
        var hashBlock = context.memory[context.laneLength - 1]
        
        for lane in 1..<context.numLanes {
            let lastBlockInLane = context.memory[lane * context.laneLength + (context.laneLength - 1)]
            hashBlock = xorBlocks(hashBlock, lastBlockInLane)
        }
        
        return Data(extendedDigest(params.tagLength, hashBlock.bytes()))
        
    }
    
    // Wrapper around Blake2b implementation that allows us to work with Data instead of [UInt8]
    private func digest(_ digestLength: Int, _ data: Data) throws -> Data {
        
        precondition(digestLength == 64, "Invalid digest length")
        
        do {
            return try Blake2b.hash(digestLength: digestLength, data: data)
        } catch {
            throw Argon2Error.blake2bFailed
        }
        
    }
    
    func ceil32(_ x: UInt32, _ y: UInt32) -> UInt32 {
        return (x + y - 1) / y
    }
    
    // Designated H' in RFC9106 - Extended digest function wrapper around Blake2b
    // Mirrors blake2b_long function in the reference implementation
    func extendedDigest(_ tagLength: UInt32, _ data: Data) -> Data {
        
        if tagLength <= 64 {
            
            return try! Blake2b.hash(digestLength: Int(tagLength), data: tagLength.littleEndian.data + data)
            
        } else {
            
            let r = ceil32(tagLength, 32) - 2
            
            // Calculate intermediate digests
            var v: [[UInt8]] = Array(repeating: [UInt8](repeating: 0, count: 64), count: Int(r+1))
            v[0] = try! Array(Blake2b.hash(digestLength: 64, data: tagLength.littleEndian.data + data))
            for i in 1..<Int(r) {
                v[i] = try! Array(Blake2b.hash(digestLength: 64, data: Data(v[i-1])))
            }
            
            // Calculate final digest
            let finalLength = Int(tagLength - 32 * r)
            v[Int(r)] = try! Array(Blake2b.hash(digestLength: finalLength, data: Data(v[Int(r-1)])))
            
            // Calculate output (first 32 bits of each intermediate digest + final digest)
            var output: [UInt8] = []
            for j in 0..<r {
                output += v[Int(j)][0..<32]
            }
            output += v[Int(r)]
            
            if output.count != tagLength {
                fatalError("Output of extendedDigest was supposed to be \(tagLength) bytes long, but was \(output.count) bytes long")
            }
            
            return Data(output)
            
        }
        
    }
    
    /// Duplicates the round function of Blake2b with some modifications
    /// #Parameters
    ///  - v: A reference to a 16-element UInt64 array
    ///  - a: An Int specifying the first element of v to use in the round
    ///  - b: An Int specifying the second element of v to use in the round
    ///  - c: An Int specifying the third element of v to use in the round
    ///  - d: An Int specifying the fourth element of v to use in the round
    func round( _ v: inout [UInt64], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        
        assert(v.count == 16, "Reference array must be 16-element long")
        
        v[a] = (v[a] &+ v[b] &+ 2 &* trunc(v[a]) &* trunc(v[b]))
        v[d] = rotateRight((v[d] ^ v[a]), by: 32)
        v[c] = (v[c] &+ v[d] &+ 2 &* trunc(v[c]) &* trunc(v[d]))
        v[b] = rotateRight((v[b] ^ v[c]), by: 24)
        
        v[a] = (v[a] &+ v[b] &+ 2 &* trunc(v[a]) &* trunc(v[b]))
        v[d] = rotateRight((v[d] ^ v[a]), by: 16)
        v[c] = (v[c] &+ v[d] &+ 2 &* trunc(v[c]) &* trunc(v[d]))
        v[b] = rotateRight((v[b] ^ v[c]), by: 63)
        
    }
    
    func permute(_ v: inout [UInt64]) {
        assert(v.count == 16, "Data must be 16 UInt64s long")
        
        round(&v, 0, 4, 8, 12)
        round(&v, 1, 5, 9, 13)
        round(&v, 2, 6, 10, 14)
        round(&v, 3, 7, 11, 15)
        
        round(&v, 0, 5, 10, 15)
        round(&v, 1, 6, 11, 12)
        round(&v, 2, 7, 8, 13)
        round(&v, 3, 4, 9, 14)
    }
    
    func permuteSlice(_ v: inout [UInt64], base: Int) {
        round(&v, base+0, base+4, base+8,  base+12)
        round(&v, base+1, base+5, base+9,  base+13)
        round(&v, base+2, base+6, base+10, base+14)
        round(&v, base+3, base+7, base+11, base+15)
        
        round(&v, base+0, base+5, base+10, base+15)
        round(&v, base+1, base+6, base+11, base+12)
        round(&v, base+2, base+7, base+8,  base+13)
        round(&v, base+3, base+4, base+9,  base+14)
    }
    
    func compress(_ prevBlock: Block, _ refBlock: Block, _ currBlock: Block? = nil) -> Block {
        
        assert(prevBlock.v.count == 128, "Incorrect (prev) data block size \(prevBlock.v.count) passed to compression function, expected 128")
        assert(refBlock.v.count == 128, "Incorrect (ref) data block size \(refBlock.v.count) passed to compression function, expected 128")
        
        // x is 1024 bytes
        // y is 1024 bytes
        // R = x XOR y is 1024 bytes, treated as a 8x8 grid of 16-byte values
        let R = xorBlocks(prevBlock, refBlock)
        
        // Apply permutation to each row
        // Each row consists of 128 Bytes, which is broken down into 8 columns of 16 Byte registers
        // Q is the array of 128 Byte values created by concatenating the the permutation of each row of R
        var Q = Block()
        
        // Iterate over the rows of R ( where a "row" consists of eight 16-byte registers, each of which contains two UInt64 values)
        // Permute each row and replace the same row in Q with the permutation result
        for idx in 0..<8 {
            
            // Set the base
            let base = 16 * idx
            
            // Copy 16 contiguous elements from R into Q
            for k in 0..<16 { Q.v[base + k] = R.v[base + k] }
            
            // Permute that slice in place
            permuteSlice(&Q.v, base: base)
            
        }
        
        // Iterate over the "columns" of Q (where a column is two UInt64 values wide), permute each row and append the result to Z
        var Z = Block()
        
        var scratch = [UInt64](repeating: 0, count: 16)
        defer { scratch.secureWipe() }
        for idx in 0..<8 {
            let indices = [
                2*idx, 2*idx+1, 2*idx+16, 2*idx+17,
                2*idx+32, 2*idx+33, 2*idx+48, 2*idx+49,
                2*idx+64, 2*idx+65, 2*idx+80, 2*idx+81,
                2*idx+96, 2*idx+97, 2*idx+112, 2*idx+113,
            ]
            for k in 0..<16 { scratch[k] = Q.v[indices[k]] }
            permute(&scratch)
            for k in 0..<16 { Z.v[indices[k]] = scratch[k] }
        }
        
        if let currBlock = currBlock {
            // This is equivalent to fill_blocks(with_xor = 1) in the reference code
            return xorBlocks(R, currBlock, Z)
        } else {
            // This is equivalent to fill_blocks(with_xor = 0) in the reference code
            return xorBlocks(R, Z)
        }
        
    }
    
    private func xorBlocks(_ a: Block, _ b: Block) -> Block {
        var result = Block()
        for i in 0..<128 {
            result.v[i] = a.v[i] ^ b.v[i]
        }
        return result
    }
    
    private func xorBlocks(_ a: Block, _ b: Block, _ c: Block) -> Block {
        var result = Block()
        for i in 0..<128 {
            result.v[i] = a.v[i] ^ b.v[i] ^ c.v[i]
        }
        return result
    }
    
}

// MARK: - Extensions for convenience

extension String {
    /// Convert string to Data using UTF-8 encoding
    var dataUsingUTF8: Data {
        return Data(self.utf8)
    }
}

extension UInt32 {
    var data: Data {
        var value = self
        return Data(bytes: &value, count: MemoryLayout<UInt32>.size)
    }
}

extension UInt64 {
    var data: Data {
        var value = self
        return Data(bytes: &value, count: MemoryLayout<UInt64>.size)
    }
}

extension Data {
    func argon2B64String() -> String {
        base64EncodedString().trimmingCharacters(in: ["="])
    }
    
    init?(argon2B64 s: String) {
        let stripped = s.trimmingCharacters(in: ["="])
        let pad = (4 - stripped.count % 4) % 4
        self.init(base64Encoded: stripped + String(repeating: "=", count: pad))
    }
}

/**
 This extensions below are very intentionally the only unsafe memory operation in the library.  Swift does not allow direct memory
 manipulation, and will optimize away writes to anything that is about to be de-allocated.  We make this one compromise
 to memory safety, and it is only used at the very end of computation when it is no longer possible to alter results.
 */

#if canImport(Darwin)
import Darwin
// Apple has memset_s available
#elseif canImport(Glibc)
import Glibc
// glibc 2.25+ has explicit_bzero, which is purpose-built for this
#endif

extension Data {
    mutating func secureWipe() {
        #if MIMICLONE_SECURE_WIPE
        withUnsafeMutableBytes { ptr in
            guard let base = ptr.baseAddress, ptr.count > 0 else { return }
            #if canImport(Darwin)
            memset_s(base, ptr.count, 0, ptr.count)
            #elseif canImport(Glibc)
            explicit_bzero(base, ptr.count)
            #endif
        }
        #else
        // Pure-Swift fallback. Note: the compiler may optimize these writes
        // away. This is documented as a non-guaranteed wipe in pure-Swift mode.
        for i in 0..<count { self[i] = 0 }
        #endif
    }
}

extension Array where Element == UInt64 {
    mutating func secureWipe() {
        #if MIMICLONE_SECURE_WIPE
        withUnsafeMutableBytes { ptr in
            guard let base = ptr.baseAddress, ptr.count > 0 else { return }
            #if canImport(Darwin)
            memset_s(base, ptr.count, 0, ptr.count)
            #elseif canImport(Glibc)
            explicit_bzero(base, ptr.count)
            #endif
        }
        #else
        // Pure-Swift fallback. Note: the compiler may optimize these writes
        // away. This is documented as a non-guaranteed wipe in pure-Swift mode.
        for i in 0..<count { self[i] = 0 }
        #endif
    }
}
