import Foundation
import Testing
@testable import SwiftArgon2


@Suite("Argon2 Test Suite")
struct SwiftArgon2TestSuite {
    
    /// Test 19 from RFC9106
    @Test func testArgon2dVersion19() async throws {
        
        let argon2 = try Argon2(params: Argon2Params(
            parallelism: 4,
            tagLength: 32,
            memorySize: 32,
            iterations: 3,
            variant: .argon2d
        ))
        
        let expectedHash = "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb"
        let hash = try await argon2.compute(
            password: dataFromHex("0101010101010101010101010101010101010101010101010101010101010101")!,
            salt: dataFromHex("02020202020202020202020202020202")!,
            secret: dataFromHex("0303030303030303")!,
            associatedData: dataFromHex("040404040404040404040404")!
        )
        #expect(hexString(from: hash) == expectedHash)
        
        let expectedEncodedHash = "$argon2d$v=19$m=32,t=3,p=4$AgICAgICAgICAgICAgICAg$USs5G28RYpdTcdMJGXNClPho4745hPPBoTpNufq+Sss"
        let encodedHash = try await argon2.computeEncoded(
            password: dataFromHex("0101010101010101010101010101010101010101010101010101010101010101")!,
            salt: dataFromHex("02020202020202020202020202020202")!,
            secret: dataFromHex("0303030303030303")!,
            associatedData: dataFromHex("040404040404040404040404")!
        )
        #expect(expectedEncodedHash == encodedHash)
        
        
    }
    
    @Test func testArgon2iVersion19() async throws {
        
        let argon2 = try Argon2(params: Argon2Params(
            parallelism: 4,
            tagLength: 32,
            memorySize: 32,
            iterations: 3,
            variant: .argon2i
        ))
        
        let expectedHash = "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8"
        let hash = try await argon2.compute(
            password: dataFromHex("0101010101010101010101010101010101010101010101010101010101010101")!,
            salt: dataFromHex("02020202020202020202020202020202")!,
            secret: dataFromHex("0303030303030303")!,
            associatedData: dataFromHex("040404040404040404040404")!
        )
        #expect(hexString(from: hash) == expectedHash)
        
        let expectedEncodedHash = "$argon2i$v=19$m=32,t=3,p=4$AgICAgICAgICAgICAgICAg$yBTZ0dx/N6oT8Nd/JJS9ocjeawFt04jSmVKkxGcrbOg"
        let encodedHash = try await argon2.computeEncoded(
            password: dataFromHex("0101010101010101010101010101010101010101010101010101010101010101")!,
            salt: dataFromHex("02020202020202020202020202020202")!,
            secret: dataFromHex("0303030303030303")!,
            associatedData: dataFromHex("040404040404040404040404")!
        )
        #expect(expectedEncodedHash == encodedHash)
        
    }
    
    @Test func testArgon2idVersion19() async throws {
        
        let argon2 = try Argon2(params: Argon2Params(
            parallelism: 4,
            tagLength: 32,
            memorySize: 32,
            iterations: 3,
            variant: .argon2id
        ))
        
        let expectedHash = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        let hash = try await argon2.compute(
            password: dataFromHex("0101010101010101010101010101010101010101010101010101010101010101")!,
            salt: dataFromHex("02020202020202020202020202020202")!,
            secret: dataFromHex("0303030303030303")!,
            associatedData: dataFromHex("040404040404040404040404")!
        )
        #expect(hexString(from: hash) == expectedHash)
        
        let expectedEncodedHash = "$argon2id$v=19$m=32,t=3,p=4$AgICAgICAgICAgICAgICAg$DWQN9Y14dmwIwDejSotTydAe8EUtdbZetSUg6WsB5lk"
        let encodedHash = try await argon2.computeEncoded(
            password: dataFromHex("0101010101010101010101010101010101010101010101010101010101010101")!,
            salt: dataFromHex("02020202020202020202020202020202")!,
            secret: dataFromHex("0303030303030303")!,
            associatedData: dataFromHex("040404040404040404040404")!
        )
        #expect(expectedEncodedHash == encodedHash)
        
    }
    
    @Test func testArgon2idVersion19Other() async throws {
        
        let argon2 = try Argon2(params: Argon2Params(
            parallelism: 4,
            tagLength: 32,
            memorySize: 32,
            iterations: 3,
            variant: .argon2id
        ))
        
        let expectedHash = "5fcdaa5b2fcf701001939de339c05902aec9fb9c28676967ee7605e59df619d2"
        let hash = try await argon2.compute(
            password: "M!m!cl0n3".dataUsingUTF8,
            salt: dataFromHex("02020202020202020202020202020202")!
        )
        #expect(hexString(from: hash) == expectedHash)
        
        let expectedEncodedHash = "$argon2id$v=19$m=32,t=3,p=4$AgICAgICAgICAgICAgICAg$X82qWy/PcBABk53jOcBZAq7J+5woZ2ln7nYF5Z32GdI"
        let encodedHash = try await argon2.computeEncoded(
            password: "M!m!cl0n3".dataUsingUTF8,
            salt: dataFromHex("02020202020202020202020202020202")!
        )
        #expect(expectedEncodedHash == encodedHash)
        
    }
    
    @Test func test_empty_secret_empty_ad_id() async throws {
        let argon2 = try Argon2(params: Argon2Params(
            parallelism: 4,
            tagLength: 32,
            memorySize: 32,
            iterations: 3,
            variant: .argon2id
        ))

        let pwd    = dataFromHex("4d216d21636c306e33")!
        let salt   = dataFromHex("02020202020202020202020202020202")!
        let secret = dataFromHex("")
        let ad     = dataFromHex("")

        let hash = try await argon2.compute(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(hexString(from: hash) == "5fcdaa5b2fcf701001939de339c05902aec9fb9c28676967ee7605e59df619d2")

        let encoded = try await argon2.computeEncoded(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(encoded == "$argon2id$v=19$m=32,t=3,p=4$AgICAgICAgICAgICAgICAg$X82qWy/PcBABk53jOcBZAq7J+5woZ2ln7nYF5Z32GdI")
    }

    @Test func test_empty_secret_with_ad_id() async throws {
        let argon2 = try Argon2(params: Argon2Params(
            parallelism: 4,
            tagLength: 32,
            memorySize: 32,
            iterations: 3,
            variant: .argon2id
        ))

        let pwd    = dataFromHex("4d216d21636c306e33")!
        let salt   = dataFromHex("02020202020202020202020202020202")!
        let secret = dataFromHex("")
        let ad     = dataFromHex("040404040404040404040404")

        let hash = try await argon2.compute(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(hexString(from: hash) == "425d5ce59b07e71530f2adf492d1d9bf5769295ef50bff432cb904205476e868")

        let encoded = try await argon2.computeEncoded(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(encoded == "$argon2id$v=19$m=32,t=3,p=4$AgICAgICAgICAgICAgICAg$Ql1c5ZsH5xUw8q30ktHZv1dpKV71C/9DLLkEIFR26Gg")
    }

    @Test func test_with_secret_empty_ad_id() async throws {
        let argon2 = try Argon2(params: Argon2Params(
            parallelism: 4,
            tagLength: 32,
            memorySize: 32,
            iterations: 3,
            variant: .argon2id
        ))

        let pwd    = dataFromHex("4d216d21636c306e33")!
        let salt   = dataFromHex("02020202020202020202020202020202")!
        let secret = dataFromHex("0303030303030303")
        let ad     = dataFromHex("")

        let hash = try await argon2.compute(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(hexString(from: hash) == "1ae4f21b21554f1e754680d0981af0758cb58486f7ebd7b4e5a9162c370b5657")

        let encoded = try await argon2.computeEncoded(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(encoded == "$argon2id$v=19$m=32,t=3,p=4$AgICAgICAgICAgICAgICAg$GuTyGyFVTx51RoDQmBrwdYy1hIb369e05akWLDcLVlc")
    }

    @Test func test_with_secret_with_ad_id() async throws {
        let argon2 = try Argon2(params: Argon2Params(
            parallelism: 4,
            tagLength: 32,
            memorySize: 32,
            iterations: 3,
            variant: .argon2id
        ))

        let pwd    = dataFromHex("4d216d21636c306e33")!
        let salt   = dataFromHex("02020202020202020202020202020202")!
        let secret = dataFromHex("0303030303030303")
        let ad     = dataFromHex("040404040404040404040404")

        let hash = try await argon2.compute(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(hexString(from: hash) == "ed4af0c9e4cc8fcb14b95c112f6d74cf94f3a8906abf58fe6efbb880a52e631a")

        let encoded = try await argon2.computeEncoded(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(encoded == "$argon2id$v=19$m=32,t=3,p=4$AgICAgICAgICAgICAgICAg$7UrwyeTMj8sUuVwRL210z5TzqJBqv1j+bvu4gKUuYxo")
    }

    @Test func test_empty_secret_empty_ad_i() async throws {
        let argon2 = try Argon2(params: Argon2Params(
            parallelism: 4,
            tagLength: 32,
            memorySize: 32,
            iterations: 3,
            variant: .argon2i
        ))

        let pwd    = dataFromHex("4d216d21636c306e33")!
        let salt   = dataFromHex("02020202020202020202020202020202")!
        let secret = dataFromHex("")
        let ad     = dataFromHex("")

        let hash = try await argon2.compute(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(hexString(from: hash) == "a3c50f97be739235159c60ea22ea206fca85f70df7ff00217013ef1221c85cdf")

        let encoded = try await argon2.computeEncoded(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(encoded == "$argon2i$v=19$m=32,t=3,p=4$AgICAgICAgICAgICAgICAg$o8UPl75zkjUVnGDqIuogb8qF9w33/wAhcBPvEiHIXN8")
    }

    @Test func test_empty_secret_empty_ad_d() async throws {
        let argon2 = try Argon2(params: Argon2Params(
            parallelism: 4,
            tagLength: 32,
            memorySize: 32,
            iterations: 3,
            variant: .argon2d
        ))

        let pwd    = dataFromHex("4d216d21636c306e33")!
        let salt   = dataFromHex("02020202020202020202020202020202")!
        let secret = dataFromHex("")
        let ad     = dataFromHex("")

        let hash = try await argon2.compute(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(hexString(from: hash) == "dc84ed0f71fdc821b93202e9d1d594f116ada59af8104d93b55956d964f4229b")

        let encoded = try await argon2.computeEncoded(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(encoded == "$argon2d$v=19$m=32,t=3,p=4$AgICAgICAgICAgICAgICAg$3ITtD3H9yCG5MgLp0dWU8RatpZr4EE2TtVlW2WT0Ips")
    }

    @Test func test_single_lane_single_pass_id() async throws {
        let argon2 = try Argon2(params: Argon2Params(
            parallelism: 1,
            tagLength: 32,
            memorySize: 8,
            iterations: 1,
            variant: .argon2id
        ))

        let pwd    = dataFromHex("4d216d21636c306e33")!
        let salt   = dataFromHex("02020202020202020202020202020202")!
        let secret = dataFromHex("")
        let ad     = dataFromHex("")

        let hash = try await argon2.compute(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(hexString(from: hash) == "9e3a142be47c70e6d46161df24b2bfd811117e5682e64bab1211aff3fb5ab92b")

        let encoded = try await argon2.computeEncoded(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(encoded == "$argon2id$v=19$m=8,t=1,p=1$AgICAgICAgICAgICAgICAg$njoUK+R8cObUYWHfJLK/2BERflaC5kurEhGv8/tauSs")
    }

    @Test func test_single_lane_three_pass_id() async throws {
        let argon2 = try Argon2(params: Argon2Params(
            parallelism: 1,
            tagLength: 32,
            memorySize: 8,
            iterations: 3,
            variant: .argon2id
        ))

        let pwd    = dataFromHex("4d216d21636c306e33")!
        let salt   = dataFromHex("02020202020202020202020202020202")!
        let secret = dataFromHex("")
        let ad     = dataFromHex("")

        let hash = try await argon2.compute(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(hexString(from: hash) == "ca8513995ae4bb350e350e531ab84a002d824bfc0a358afeca1b9375515e5622")

        let encoded = try await argon2.computeEncoded(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(encoded == "$argon2id$v=19$m=8,t=3,p=1$AgICAgICAgICAgICAgICAg$yoUTmVrkuzUONQ5TGrhKAC2CS/wKNYr+yhuTdVFeViI")
    }

    @Test func test_four_lane_single_pass_id() async throws {
        let argon2 = try Argon2(params: Argon2Params(
            parallelism: 4,
            tagLength: 32,
            memorySize: 32,
            iterations: 1,
            variant: .argon2id
        ))

        let pwd    = dataFromHex("4d216d21636c306e33")!
        let salt   = dataFromHex("02020202020202020202020202020202")!
        let secret = dataFromHex("")
        let ad     = dataFromHex("")

        let hash = try await argon2.compute(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(hexString(from: hash) == "c60f896c94c3ebd3f0efd5a185689ca6bc545e125ea720c72f562724a354fb1e")

        let encoded = try await argon2.computeEncoded(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(encoded == "$argon2id$v=19$m=32,t=1,p=4$AgICAgICAgICAgICAgICAg$xg+JbJTD69Pw79WhhWicprxUXhJepyDHL1YnJKNU+x4")
    }

    @Test func test_larger_memory_id() async throws {
        let argon2 = try Argon2(params: Argon2Params(
            parallelism: 2,
            tagLength: 32,
            memorySize: 256,
            iterations: 2,
            variant: .argon2id
        ))

        let pwd    = dataFromHex("4d216d21636c306e33")!
        let salt   = dataFromHex("02020202020202020202020202020202")!
        let secret = dataFromHex("")
        let ad     = dataFromHex("")

        let hash = try await argon2.compute(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(hexString(from: hash) == "5ee0c45f352154414bf3b773399969515f5c82825c2ee99e8c2344b894da33fe")

        let encoded = try await argon2.computeEncoded(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(encoded == "$argon2id$v=19$m=256,t=2,p=2$AgICAgICAgICAgICAgICAg$XuDEXzUhVEFL87dzOZlpUV9cgoJcLumejCNEuJTaM/4")
    }

    @Test func test_tag_64_id() async throws {
        let argon2 = try Argon2(params: Argon2Params(
            parallelism: 4,
            tagLength: 64,
            memorySize: 32,
            iterations: 3,
            variant: .argon2id
        ))

        let pwd    = dataFromHex("4d216d21636c306e33")!
        let salt   = dataFromHex("02020202020202020202020202020202")!
        let secret = dataFromHex("")
        let ad     = dataFromHex("")

        let hash = try await argon2.compute(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(hexString(from: hash) == "83549158b844f555cf9f8858e512626e131b9e23565a68c8b18e2174a6f09656f316e3f36519875a5a653ff5dc7a1a500a8af58fcd3da5c80b29236276ad42d1")

        let encoded = try await argon2.computeEncoded(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(encoded == "$argon2id$v=19$m=32,t=3,p=4$AgICAgICAgICAgICAgICAg$g1SRWLhE9VXPn4hY5RJibhMbniNWWmjIsY4hdKbwllbzFuPzZRmHWlplP/XcehpQCor1j809pcgLKSNidq1C0Q")
    }

    @Test func test_tag_16_id() async throws {
        let argon2 = try Argon2(params: Argon2Params(
            parallelism: 4,
            tagLength: 16,
            memorySize: 32,
            iterations: 3,
            variant: .argon2id
        ))

        let pwd    = dataFromHex("4d216d21636c306e33")!
        let salt   = dataFromHex("02020202020202020202020202020202")!
        let secret = dataFromHex("")
        let ad     = dataFromHex("")

        let hash = try await argon2.compute(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(hexString(from: hash) == "ea77398914b2546ba803f601552fdbef")

        let encoded = try await argon2.computeEncoded(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(encoded == "$argon2id$v=19$m=32,t=3,p=4$AgICAgICAgICAgICAgICAg$6nc5iRSyVGuoA/YBVS/b7w")
    }

    @Test func test_different_salt_id() async throws {
        let argon2 = try Argon2(params: Argon2Params(
            parallelism: 4,
            tagLength: 32,
            memorySize: 32,
            iterations: 3,
            variant: .argon2id
        ))

        let pwd    = dataFromHex("4d216d21636c306e33")!
        let salt   = dataFromHex("05050505050505050505050505050505")!
        let secret = dataFromHex("")
        let ad     = dataFromHex("")

        let hash = try await argon2.compute(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(hexString(from: hash) == "a462923080663880229badd9c371169497d5b8a3d65ac5069183698cf9bc5e86")

        let encoded = try await argon2.computeEncoded(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(encoded == "$argon2id$v=19$m=32,t=3,p=4$BQUFBQUFBQUFBQUFBQUFBQ$pGKSMIBmOIAim63Zw3EWlJfVuKPWWsUGkYNpjPm8XoY")
    }

    @Test func test_production_params_id() async throws {
        let argon2 = try Argon2(params: Argon2Params(
            parallelism: 4,
            tagLength: 32,
            memorySize: 65536,
            iterations: 3,
            variant: .argon2id
        ))

        let pwd    = dataFromHex("4d216d21636c306e33")!
        let salt   = dataFromHex("02020202020202020202020202020202")!
        let secret = dataFromHex("")
        let ad     = dataFromHex("")

        let hash = try await argon2.compute(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(hexString(from: hash) == "11aab297e6d291baa018cd7678a2323d8b5609f44102f46b731cebb3c2578518")

        let encoded = try await argon2.computeEncoded(
            password: pwd, salt: salt, secret: secret, associatedData: ad
        )
        #expect(encoded == "$argon2id$v=19$m=65536,t=3,p=4$AgICAgICAgICAgICAgICAg$Eaqyl+bSkbqgGM12eKIyPYtWCfRBAvRrcxzrs8JXhRg")
    }
    
    private func dataFromHex(_ hexString: String) -> Data? {
        let hexStr = hexString.replacingOccurrences(of: " ", with: "")
        var data = Data(capacity: hexStr.count / 2)
        
        for i in stride(from: 0, to: hexStr.count, by: 2) {
            let startIndex = hexStr.index(hexStr.startIndex, offsetBy: i)
            let endIndex = hexStr.index(startIndex, offsetBy: 2, limitedBy: hexStr.endIndex) ?? hexStr.endIndex
            let bytes = hexStr[startIndex..<endIndex]
            
            if let byte = UInt8(bytes, radix: 16) {
                data.append(byte)
            } else {
                return nil
            }
        }
        
        return data
    }
    
    private func hexString(from data: Data) -> String {
        return data.map { String(format: "%02x", $0) }.joined()
    }
    
}
