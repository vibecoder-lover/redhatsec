import Foundation
import Combine

// Esecuzione root via sudo -S: la password va su stdin (runWithStdin).
// Niente helper setuid, niente storage: la password vive solo in RAM per la sessione.
final class RootShell: ObservableObject {
    static let shared = RootShell()

    @Published var password: String = ""
    @Published var lastRootOK = false

    var available: Bool {
        ShellRunner.shared.resolve("sudo") != nil
    }

    static let rootEnv =
        "export PATH=/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin:" +
        "/var/jb/usr/local/bin:/var/mobile/RedHatSec/bin:/usr/bin:/bin:/usr/sbin:/sbin;" +
        " export DEBIAN_FRONTEND=noninteractive;"

    private func sudoArgs(_ cmd: String) -> [String] {
        let wrapped = "\(Self.rootEnv) \(cmd)"
        return ["-S", "-p", "", "sh", "-c", wrapped]
    }

    func runSync(_ cmd: String, timeout: TimeInterval = 180) -> ShellResult {
        guard available else {
            return ShellResult(exitCode: 127, stdout: "",
                               stderr: "sudo non presente nel bootstrap — installa il pacchetto 'sudo' da Sileo una volta")
        }
        let stdinData = Data("\(password)\n".utf8)
        let r = ShellRunner.shared.runWithStdin("sudo", args: sudoArgs(cmd), stdin: stdinData, timeout: timeout)
        lastRootOK = r.exitCode == 0
        return r
    }

    func run(_ cmd: String, timeout: TimeInterval = 180) async -> ShellResult {
        await Task.detached { [self] in
            self.runSync(cmd, timeout: timeout)
        }.value
    }
}
