import SwiftUI

@main
struct RedHatSecApp: App {
    @StateObject private var o = Orchestrator()

    var body: some Scene {
        WindowGroup {
            TabView {
                DashboardView()
                    .tabItem { Label("Orchestrator", systemImage: "bolt.horizontal.fill") }
                CatalogView()
                    .tabItem { Label("Vectors", systemImage: "square.grid.2x2.fill") }
                TargetsView()
                    .tabItem { Label("Targets", systemImage: "sensor.tag.radiowaves.forward.fill") }
                ReportView()
                    .tabItem { Label("Report", systemImage: "doc.text.below.ecg.fill") }
            }
            .tint(.redHat)
            .preferredColorScheme(.dark)
            .environmentObject(o)
        }
    }
}
