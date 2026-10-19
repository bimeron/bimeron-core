import Foundation
import Security

enum ProfileStore {
    static func query(_ id: String) -> [String: Any] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecUseDataProtectionKeychain as String: true,
            kSecAttrService as String: "BimeronCoreProfile", kSecAttrAccount as String: id]
        if let group = Bundle.main.object(forInfoDictionaryKey: "RLKeychainGroup") as? String, !group.isEmpty {
            q[kSecAttrAccessGroup as String] = group
        }
        return q
    }
    static func read(_ id: String) throws -> Data {
        var q = query(id); q[kSecReturnData as String] = true
        var value: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &value) == errSecSuccess, let data = value as? Data else {
            throw NSError(domain: "Bimeron", code: 1, userInfo: [NSLocalizedDescriptionKey: "Profile unavailable in shared Keychain"])
        }
        return data
    }
    static func write(_ id: String, _ data: Data) throws {
        var q = query(id); q[kSecValueData as String] = data
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        guard SecItemAdd(q as CFDictionary, nil) == errSecSuccess else {
            throw NSError(domain: "Bimeron", code: 2, userInfo: [NSLocalizedDescriptionKey: "Cannot store profile in shared Keychain"])
        }
    }
    static func remove(_ id: String) { SecItemDelete(query(id) as CFDictionary) }
}
