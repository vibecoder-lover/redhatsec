import SwiftUI

@main
struct RedHatSecApp: App {
    @StateObject private var o = Orchestrator()

    var body: some Scene {
        WindowGroup {
            TabView {
                DashboardView()
                    .tabItem { Label("Orchestrator", systemImage: "bolt.horizontal.fill") }
                TargetsView()
                    .tabItem { Label("Targets", systemImage: "sensor.tag.radiowaves.forward.fill") }
                CatalogView()
                    .tabItem { Label("Vectors", systemImage: "square.grid.2x2.fill") }
                ToolsTab()
                    .tabItem { Label("Tools", systemImage: "hammer.circle.fill") }
                ReportView()
                    .tabItem { Label("Report", systemImage: "doc.text.below.ecg.fill") }
            }
            .tint(.redHat)
            .preferredColorScheme(.dark)
            .environmentObject(o)
        }
    }
}
