import Foundation

// Traccia forense che sopravvive al crash: ogni step critico scrive qui.
// Se l'app muore, il file dice ESATTAMENTE dove — l'ultima riga senza "ok" è il punto.
enum CrashTracer {
    // le callback NW/BLE/Task scrivono da thread diversi: appendi serializzato
    private static let q = DispatchQueue(label: "rhs.crashtracer")

    static func mark(_ s: String) {
        q.async {
            let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
                ?? URL(fileURLWithPath: NSTemporaryDirectory())
            let f = docs.appendingPathComponent("crash_trace.txt")
            // cap 256KB: TIENI la coda (la storia recente), non cancellare tutto
            if let sz = (try? f.resourceValues(forKeys: [.fileSizeKey]))?.fileSize, sz > 256_000,
               let blob = try? Data(contentsOf: f) {
                try? Data(blob.suffix(128_000)).write(to: f, options: .atomic)
            }
            let line = "[\(DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium))] \(s)\n"
            if let fh = try? FileHandle(forWritingTo: f) {
                _ = try? fh.seekToEnd()
                try? fh.write(contentsOf: Data(line.utf8))
                try? fh.synchronize()
                try? fh.close()
            } else {
                try? line.write(to: f, atomically: true, encoding: .utf8)
            }
        }
    }

    static func clear() {
        q.sync {
            let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
                ?? URL(fileURLWithPath: NSTemporaryDirectory())
            try? FileManager.default.removeItem(at: docs.appendingPathComponent("crash_trace.txt"))
        }
    }
}
