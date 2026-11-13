import Foundation
import Security

/// Where a cluster's refresh token is kept, by account (the context's id). Never the app's defaults
/// or a plain file.
public protocol TokenVault: Sendable {
    func read(_ account: String) throws -> Data?
    func write(_ account: String, _ data: Data) throws
    func delete(_ account: String) throws
}

public enum KeychainError: Error, Equatable, CustomStringConvertible {
    case status(OSStatus, String)
    public var description: String {
        switch self {
        case .status(let s, let op):
            let msg = (SecCopyErrorMessageString(s, nil) as String?) ?? "OSStatus \(s)"
            return "keychain \(op): \(msg)"
        }
    }
}

/// Generic-password items in the person's login keychain, under the app's own service name. It is
/// not `kvo`'s (`com.kevaso.kvo`): the app neither reads nor writes kvo's sessions, and signing
/// out of one leaves the other signed in. Tests use a service name of their own and delete it.
public struct KeychainVault: TokenVault {
    public static let appService = "com.kevaso.panes"
    public let service: String

    public init(service: String = KeychainVault.appService) {
        precondition(service != "com.kevaso.kvo", "that is kvo's keychain service")
        self.service = service
    }

    private func query(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    public func read(_ account: String) throws -> Data? {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let s = SecItemCopyMatching(q as CFDictionary, &out)
        if s == errSecItemNotFound { return nil }
        guard s == errSecSuccess else { throw KeychainError.status(s, "read") }
        return out as? Data
    }

    public func write(_ account: String, _ data: Data) throws {
        let s = SecItemUpdate(query(account) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if s == errSecSuccess { return }
        guard s == errSecItemNotFound else { throw KeychainError.status(s, "update") }
        var add = query(account)
        add[kSecValueData as String] = data
        add[kSecAttrLabel as String] = "Kevaso Panes sign-in"
        add[kSecAttrDescription as String] = "Kevaso refresh token"
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked
        let a = SecItemAdd(add as CFDictionary, nil)
        guard a == errSecSuccess else { throw KeychainError.status(a, "add") }
    }

    public func delete(_ account: String) throws {
        let s = SecItemDelete(query(account) as CFDictionary)
        guard s == errSecSuccess || s == errSecItemNotFound else { throw KeychainError.status(s, "delete") }
    }

    /// Every account under this service (for tests' cleanup and the app's "remove cluster").
    public func accounts() throws -> [String] {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecReturnAttributes as String: true, kSecMatchLimit as String: kSecMatchLimitAll]
        var out: CFTypeRef?
        let s = SecItemCopyMatching(q as CFDictionary, &out)
        if s == errSecItemNotFound { return [] }
        guard s == errSecSuccess else { throw KeychainError.status(s, "list") }
        return (out as? [[String: Any]] ?? []).compactMap { $0[kSecAttrAccount as String] as? String }
    }

    /// Deletes every item under this service.
    public func deleteAll() throws {
        for a in try accounts() { try delete(a) }
    }
}

/// A vault in memory, for code that must not touch any keychain.
public final class MemoryVault: TokenVault, @unchecked Sendable {
    private var items: [String: Data] = [:]
    private let lock = NSLock()
    public init() {}
    public func read(_ account: String) throws -> Data? { lock.lock(); defer { lock.unlock() }; return items[account] }
    public func write(_ account: String, _ data: Data) throws { lock.lock(); defer { lock.unlock() }; items[account] = data }
    public func delete(_ account: String) throws { lock.lock(); defer { lock.unlock() }; items[account] = nil }
}
