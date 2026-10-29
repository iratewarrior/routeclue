import SwiftUI
import TunnelGuardCore

@main
struct TunnelGuardApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        MenuBarExtra {
            MenuContent(model: model)
        } label: {
            Image(systemName: model.statusSymbol)
        }
        .menuBarExtraStyle(.menu)

        Window("TunnelGuard — diagnostics", id: "doctor") {
            DoctorView(model: model)
                .frame(minWidth: 560, minHeight: 420)
                .onAppear { model.refresh() }
        }
        .windowResizability(.contentMinSize)
    }
}

final class AppModel: ObservableObject {
    @Published var report: DiagnosticReport?
    @Published var killSwitchEnabled: Bool?
    @Published var isBusy = false
    @Published var lastMessage: String?

    private let config = ConfigStore.load()

    var statusSymbol: String {
        if isBusy { return "hourglass" }
        if report?.tunnelUp == false { return "exclamationmark.shield" }
        if killSwitchEnabled == true { return "lock.shield.fill" }
        return "shield"
    }

    func refresh() {
        DispatchQueue.global(qos: .userInitiated).async {
            let snapshot = Diagnostics.snapshot(config: self.config)
            let killSwitch = KillSwitch.isEnabled()
            DispatchQueue.main.async {
                self.report = snapshot
                self.killSwitchEnabled = killSwitch
            }
        }
    }

    func toggleKillSwitch() {
        let turningOff = killSwitchEnabled == true
        run(title: turningOff ? "Disabling kill switch…" : "Enabling kill switch…") {
            if turningOff {
                return try KillSwitch.disable()
            }
            let plan = try KillSwitch.apply(self.config)
            return "Kill switch enabled on: \(plan.interfaces.joined(separator: ", "))"
        }
    }

    func ensureRoutes() {
        run(title: "Recreating routes…") {
            try RouteManager.ensure(self.config).joined(separator: "\n")
        }
    }

    func removeRoutes() {
        run(title: "Removing routes…") {
            try RouteManager.remove(self.config).joined(separator: "\n")
        }
    }

    func applyDNS() {
        run(title: "Applying DNS zones…") {
            try DNSZones.apply(self.config.dnsZones)
        }
    }

    private func run(title: String, _ work: @escaping () throws -> String) {
        isBusy = true
        lastMessage = title
        DispatchQueue.global(qos: .userInitiated).async {
            let outcome: String
            do {
                outcome = try work()
            } catch {
                outcome = "Error: \(error)"
            }
            DispatchQueue.main.async {
                self.isBusy = false
                self.lastMessage = outcome
                self.refresh()
            }
        }
    }
}

struct MenuContent: View {
    @ObservedObject var model: AppModel

    var body: some View {
        Group {
            if let report = model.report {
                Text("LAN: \(report.lanAddress ?? "—") → \(report.gateway ?? "—")")
                Text("Tunnel: \(report.tunnelUp ? "up" : "down")")
                Text("Exit address: \(report.exitIP ?? "—")")
                if let enabled = model.killSwitchEnabled {
                    Text("Kill switch: \(enabled ? "on" : "off")")
                }
            } else {
                Text("Collecting state…")
            }

            Divider()

            Button(model.killSwitchEnabled == true ? "Disable kill switch" : "Enable kill switch") {
                model.toggleKillSwitch()
            }
            .disabled(model.isBusy)

            Button("Recreate corporate routes") { model.ensureRoutes() }
                .disabled(model.isBusy)

            Button("Remove corporate routes") { model.removeRoutes() }
                .disabled(model.isBusy)

            Button("Apply DNS zones") { model.applyDNS() }
                .disabled(model.isBusy)

            Divider()

            Button("Diagnostics…") {
                NSApp.activate(ignoringOtherApps: true)
                NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
            }

            Button("Refresh") { model.refresh() }

            Divider()

            Button("Quit") { NSApp.terminate(nil) }
        }
        .onAppear { model.refresh() }
    }

    private func openDoctor() {
        NSApp.activate(ignoringOtherApps: true)
        if let window = NSApp.windows.first(where: { $0.title.contains("diagnostics") }) {
            window.makeKeyAndOrderFront(nil)
        }
    }
}

struct DoctorView: View {
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Network state")
                    .font(.title2.bold())
                Spacer()
                Button("Refresh") { model.refresh() }
                    .disabled(model.isBusy)
            }

            ScrollView {
                Text(model.report?.summary ?? "Collecting state…")
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(12)
            .background(Color(nsColor: .textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 8))

            if let message = model.lastMessage {
                Text(message)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        }
        .padding(16)
    }
}
