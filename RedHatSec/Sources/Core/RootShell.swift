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
        // A) persona spawn diretto di sh del bootstrap (uid 0 override)
        let a = ShellRunner.shared.runWithStdin("sh", args: ["-c", wrapped], stdin: nil, asRoot: true, timeout: timeout)
        guard a.stderr.contains("spawn failed") else {
            lastRootOK = a.exitCode == 0
            return a
        }
        // B) helper nel bundle — lo spawn in-container è sempre permesso; l'helper
        // nasce root (persona) e fa lui l'exec di sh, con diagnostica EXECFAIL
        let helper = Bundle.main.bundlePath + "/RHSHelper"
        guard FileManager.default.fileExists(atPath: helper) else {
            var r = a
            r.stderr += "\n[RHSHelper] assente nel bundle"
            return r
        }
        let b = ShellRunner.shared.runPath(helper, args: [wrapped], stdin: nil, asRoot: true, timeout: timeout)
        lastRootOK = b.exitCode == 0
        return b
    }

    func run(_ cmd: String, timeout: TimeInterval = 180) async -> ShellResult {
        await Task.detached { [self] in
            self.runSync(cmd, timeout: timeout)
        }.value
    }
}
