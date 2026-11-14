import Foundation
import Combine

// Root via persona spawn: posix_spawnattr_set_persona_np con override uid/gid 0.
// Niente sudo, niente setuid (l'AMFI li nega). Richiede l'entitlement
// com.apple.private.persona-mgmt (in RedHatSec.entitlements). La password
// resta in RAM ma non serve più per l'esecuzione.
final class RootShell: ObservableObject {
    static let shared = RootShell()

    @Published var password: String = ""
    @Published var lastRootOK = false

    var available: Bool {
        ShellRunner.shared.resolve("sh") != nil
    }

    func runSync(_ cmd: String, timeout: TimeInterval = 180) -> ShellResult {
        let wrapped = "export DEBIAN_FRONTEND=noninteractive; \(cmd)"
        let r = ShellRunner.shared.runWithStdin("sh", args: ["-c", wrapped], stdin: nil, asRoot: true, timeout: timeout)
        lastRootOK = r.exitCode == 0
        return r
    }

    func run(_ cmd: String, timeout: TimeInterval = 180) async -> ShellResult {
        await Task.detached { [self] in
            self.runSync(cmd, timeout: timeout)
        }.value
    }
}
