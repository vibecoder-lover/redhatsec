import Foundation
import Combine

// Esecuzione root via sudo -S. NOTA: sudo e' setuid — l'AMFI nega all'app l'exec
// diretto di binari setuid (EPERM allo spawn). Quindi lo spawn lo fa `sh` del
// bootstrap (caller platform-signed), che a sua volta exec'xa sudo. La password
// va su stdin di sudo (-S); vive solo in RAM per la sessione.
final class RootShell: ObservableObject {
    static let shared = RootShell()

    @Published var password: String = ""
    @Published var lastRootOK = false

    var available: Bool {
        ShellRunner.shared.resolve("sudo") != nil
    }

    func runSync(_ cmd: String, timeout: TimeInterval = 180) -> ShellResult {
        guard available else {
            return ShellResult(exitCode: 127, stdout: "",
                               stderr: "sudo non presente nel bootstrap — installa il pacchetto 'sudo' da Sileo una volta")
        }
        let esc = cmd.replacingOccurrences(of: "'", with: "'\\''")
        let wrapped = "sudo -S -p '' env PATH=/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin:" +
            "/var/jb/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin DEBIAN_FRONTEND=noninteractive sh -c '\(esc)'"
        let stdinData = Data("\(password)\n".utf8)
        let r = ShellRunner.shared.runWithStdin("sh", args: ["-c", wrapped], stdin: stdinData, timeout: timeout)
        lastRootOK = r.exitCode == 0
        return r
    }

    func run(_ cmd: String, timeout: TimeInterval = 180) async -> ShellResult {
        await Task.detached { [self] in
            self.runSync(cmd, timeout: timeout)
        }.value
    }
}
