import Foundation

// Traccia forense che sopravvive al crash: ogni step critico scrive qui.
// Se l'app muore, il file dice ESATTAMENTE dove — l'ultima riga senza "ok" è il punto.
enum CrashTracer {
    static func mark(_ s: String) {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let f = docs.appendingPathComponent("crash_trace.txt")
        // cap 256KB: ricrea il file
        if let sz = (try? f.resourceValues(forKeys: [.fileSizeKey]))?.fileSize, sz > 256_000 {
            try? FileManager.default.removeItem(at: f)
        }
        let line = "[\(DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium))] \(s)\n"
        if let fh = try? FileHandle(forWritingTo: f) {
            _ = try? fh.seekToEnd()
            try? fh.write(contentsOf: Data(line.utf8))
            try? fh.close()
        } else {
            try? line.write(to: f, atomically: true, encoding: .utf8)
        }
    }

    static func clear() {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        try? FileManager.default.removeItem(at: docs.appendingPathComponent("crash_trace.txt"))
    }
}
