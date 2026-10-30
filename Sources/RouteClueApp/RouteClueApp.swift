import SwiftUI
import Network
import RouteClueCore

@main
struct RouteClueApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        MenuBarExtra {
            PopoverContentView(model: model)
                .frame(width: 420)
        } label: {
            Image(systemName: model.statusSymbol)
        }
        .menuBarExtraStyle(.window)

        Window("RouteClue — Diagnostics & Doctor", id: "doctor") {
            DoctorWindowView(model: model)
                .frame(minWidth: 640, minHeight: 520)
        }
        .windowResizability(.contentMinSize)
    }
}

// MARK: - AppModel

@MainActor
final class AppModel: ObservableObject {
    @Published var report: DiagnosticReport?
    @Published var killSwitchEnabled: Bool?
    @Published var isBusy = false
    @Published var lastMessage: String?
    @Published var inputHost: String = ""
    @Published var inputValidationError: String?
    @Published var inputExplanation: PathExplanation?
    @Published var configError: String?

    private var config: RouteClueConfig = RouteClueConfig()
    private let pathMonitor = NWPathMonitor()
    private let monitorQueue = DispatchQueue(label: "dev.routeclue.pathmonitor")
    private var debounceTask: Task<Void, Never>?
    private var isRefreshing = false
    private var needsAnotherRefresh = false

    init() {
        reloadConfig()
        startNetworkMonitoring()
        refresh()
    }

    var statusSymbol: String {
        if isBusy { return "hourglass" }
        if report?.tunnelUp == false { return "exclamationmark.shield" }
        if killSwitchEnabled == true { return "lock.shield.fill" }
        if killSwitchEnabled == nil { return "questionmark.shield" }
        return "shield"
    }

    func reloadConfig() {
        do {
            self.config = try ConfigStore.load()
            self.configError = nil
        } catch {
            self.configError = error.localizedDescription
            self.lastMessage = "Config error: \(error.localizedDescription)"
        }
    }

    private func startNetworkMonitoring() {
        pathMonitor.pathUpdateHandler = { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.scheduleDebouncedRefresh()
            }
        }
        pathMonitor.start(queue: monitorQueue)
    }

    func scheduleDebouncedRefresh() {
        debounceTask?.cancel()
        debounceTask = Task { @MainActor in
            try? await Task.sleep(nanoseconds: 350_000_000) // 350ms debounce
            if !Task.isCancelled {
                self.refresh()
            }
        }
    }

    func refresh() {
        if isRefreshing {
            needsAnotherRefresh = true
            return
        }
        isRefreshing = true

        Task {
            reloadConfig()
            let cfg = self.config
            let snapshot = await Task.detached(priority: .userInitiated) {
                Diagnostics.snapshot(config: cfg)
            }.value

            let ks = await Task.detached(priority: .userInitiated) {
                KillSwitch.isEnabled()
            }.value

            self.report = snapshot
            self.killSwitchEnabled = ks
            self.isRefreshing = false

            if self.needsAnotherRefresh {
                self.needsAnotherRefresh = false
                self.refresh()
            }
        }
    }

    func setInputHost(_ text: String) {
        switch TargetInputNormalizer.normalize(text) {
        case let .success(normalized):
            self.inputHost = normalized
            self.inputValidationError = nil
            self.inputExplanation = nil
        case let .failure(error):
            self.inputHost = text.trimmingCharacters(in: .whitespacesAndNewlines)
            self.inputValidationError = error.localizedDescription
            self.inputExplanation = nil
        }
    }

    func explainInput() {
        let trimmed = inputHost.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }

        // Валидация перед отправкой любых запросов к сети/DNS
        let targetHost: String
        switch TargetInputNormalizer.normalize(trimmed) {
        case let .success(normalized):
            targetHost = normalized
            self.inputValidationError = nil
        case let .failure(error):
            self.inputValidationError = error.localizedDescription
            self.inputExplanation = nil
            return
        }

        let cfg = config
        Task {
            let explanation = await Task.detached(priority: .userInitiated) {
                PathExplainer.explain(host: targetHost, config: cfg)
            }.value
            self.inputExplanation = explanation
        }
    }

    func enableKillSwitch() {
        guard configError == nil else {
            lastMessage = "Блокировано: исправьте ошибку в config.json перед включением kill switch."
            return
        }
        let cfg = config
        run(title: "Включение kill switch…") {
            let plan = try KillSwitch.apply(cfg)
            return "Kill switch включен на интерфейсах: \(plan.interfaces.joined(separator: ", "))"
        }
    }

    func disableKillSwitch() {
        // Emergency recovery: всегда разрешено даже при наличии configError
        run(title: "Отключение kill switch (recovery)…") {
            return try KillSwitch.disable()
        }
    }

    func ensureRoutes() {
        guard configError == nil else {
            lastMessage = "Блокировано: исправьте ошибку в config.json перед применением маршрутов."
            return
        }
        let cfg = config
        run(title: "Восстановление корпоративных маршрутов…") {
            try RouteManager.ensure(cfg).joined(separator: "\n")
        }
    }

    func removeRoutes() {
        let cfg = config
        run(title: "Удаление корпоративных маршрутов…") {
            try RouteManager.remove(cfg).joined(separator: "\n")
        }
    }

    func applyDNS() {
        guard configError == nil else {
            lastMessage = "Блокировано: исправьте ошибку в config.json перед синхронизацией DNS."
            return
        }
        let cfg = config
        run(title: "Применение DNS зон…") {
            try DNSZones.apply(cfg.dnsZones)
        }
    }

    func flushDNS() {
        run(title: "Очистка кэша DNS…") {
            try DNSZones.flush()
            return "Кэш DNS успешно очищен."
        }
    }

    func healAll() {
        guard configError == nil else {
            lastMessage = "Блокировано: исправьте ошибку в config.json перед выполнением Heal All."
            return
        }
        let cfg = config
        run(title: "Восстановление состояния сети…") {
            var log: [String] = []
            if !cfg.corpSubnets.isEmpty {
                do {
                    let routesLog = try RouteManager.ensure(cfg)
                    log.append(contentsOf: routesLog)
                } catch {
                    log.append("Ошибка маршрутов: \(error)")
                }
            } else {
                log.append("Подсети не настроены.")
            }

            if !cfg.dnsZones.isEmpty {
                do {
                    let dnsLog = try DNSZones.apply(cfg.dnsZones)
                    log.append(dnsLog)
                } catch {
                    log.append("Ошибка DNS зон: \(error)")
                }
            } else {
                log.append("DNS зоны не настроены.")
            }
            return log.joined(separator: "\n")
        }
    }

    private func run(title: String, _ work: @escaping @Sendable () throws -> String) {
        isBusy = true
        lastMessage = title
        Task {
            let outcome: String
            do {
                outcome = try await Task.detached(priority: .userInitiated) {
                    try work()
                }.value
            } catch {
                outcome = "Ошибка: \(error)"
            }
            self.isBusy = false
            self.lastMessage = outcome
            self.refresh()
        }
    }
}

// MARK: - Menu Bar Window Popover

struct PopoverContentView: View {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(spacing: 12) {
            // Header Hero
            HStack(spacing: 12) {
                Image(systemName: model.statusSymbol)
                    .font(.system(size: 28, weight: .semibold))
                    .foregroundStyle(statusColor)

                VStack(alignment: .leading, spacing: 2) {
                    Text("RouteClue")
                        .font(.headline)
                    HStack(spacing: 6) {
                        Circle()
                            .fill(model.report?.tunnelUp == true ? Color.green : Color.orange)
                            .frame(width: 8, height: 8)
                        Text(model.report?.tunnelUp == true ? "VPN Connected (\(model.report?.tunnelInterface ?? "tun"))" : "VPN Offline")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                Spacer()

                if let ip = model.report?.exitIP {
                    Text(ip)
                        .font(.system(.caption2, design: .monospaced))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(Color.primary.opacity(0.06))
                        .clipShape(Capsule())
                }
            }
            .padding(.horizontal, 16)
            .padding(.top, 14)

            if let err = model.configError {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                    Text(err)
                        .font(.caption2)
                        .foregroundStyle(.red)
                        .lineLimit(2)
                }
                .padding(.horizontal, 16)
            }

            Divider()

            // Diagnostics Input Card (Explicit Input & Paste with TargetNormalizer)
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(.blue)
                    TextField("Host, URL, or IPv6 to inspect…", text: $model.inputHost)
                        .textFieldStyle(.roundedBorder)
                        .font(.caption)

                    Button {
                        if let text = NSPasteboard.general.string(forType: .string)?.trimmingCharacters(in: .whitespacesAndNewlines), !text.isEmpty {
                            model.setInputHost(text)
                        }
                    } label: {
                        Label("Paste", systemImage: "doc.on.clipboard")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.mini)

                    Button("Check") {
                        model.explainInput()
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.mini)
                    .disabled(model.inputHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }

                if let valError = model.inputValidationError {
                    Text("✖ \(valError)")
                        .font(.caption2)
                        .foregroundStyle(.red)
                }

                if let expl = model.inputExplanation {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text("Verdict:")
                                .font(.caption2.bold())
                            Text(expl.verdict.rawValue)
                                .font(.caption2.bold())
                                .foregroundStyle(verdictColor(expl.verdict))
                        }
                        if let addr = expl.addresses.first {
                            Text("DNS: \(addr)")
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundStyle(.secondary)
                        }
                        if let path = expl.paths.first {
                            Text("Interface: \(path.interface ?? "none") via \(path.gateway ?? "none")")
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundStyle(.secondary)
                        }
                    }
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.blue.opacity(0.08))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                }
            }
            .padding(10)
            .background(Color(nsColor: .controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .padding(.horizontal, 16)

            // Quick Status & Controls
            VStack(spacing: 10) {
                // Kill Switch Row: handles true, false, and unknown distinctly
                HStack {
                    Label("Kill Switch", systemImage: "shield.checkered")
                        .font(.subheadline)
                    Spacer()

                    if model.killSwitchEnabled == nil {
                        // Unknown state: display explicit Enable and Disable (Recovery) buttons
                        HStack(spacing: 6) {
                            Text("Unknown")
                                .font(.caption2)
                                .foregroundStyle(.orange)
                            Button("Enable") {
                                model.enableKillSwitch()
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.mini)
                            .disabled(model.isBusy || model.configError != nil)

                            Button("Disable") {
                                model.disableKillSwitch()
                            }
                            .buttonStyle(.borderedProminent)
                            .tint(.red)
                            .controlSize(.mini)
                            .disabled(model.isBusy)
                        }
                    } else {
                        // Known state: binding respects requested bool directly
                        Text(model.killSwitchEnabled == true ? "Active (on)" : "Inactive (off)")
                            .font(.caption2)
                            .foregroundStyle(model.killSwitchEnabled == true ? Color.green : Color.secondary)

                        Toggle("", isOn: Binding(
                            get: { model.killSwitchEnabled == true },
                            set: { requested in
                                if requested {
                                    model.enableKillSwitch()
                                } else {
                                    model.disableKillSwitch()
                                }
                            }
                        ))
                        .toggleStyle(.switch)
                        .controlSize(.mini)
                        .disabled(model.isBusy || (model.killSwitchEnabled == false && model.configError != nil))
                    }
                }

                // Routes Row
                HStack {
                    Label("Corporate Routes", systemImage: "point.topleft.down.to.point.bottomright.curvepath")
                        .font(.subheadline)
                    Spacer()
                    Button("Heal") {
                        model.ensureRoutes()
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.mini)
                    .disabled(model.isBusy || model.configError != nil)
                }

                // DNS Row
                HStack {
                    Label("Split DNS Zones", systemImage: "network")
                        .font(.subheadline)
                    Spacer()
                    Button("Apply") {
                        model.applyDNS()
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.mini)
                    .disabled(model.isBusy || model.configError != nil)
                }
            }
            .padding(.horizontal, 16)

            Divider()

            // Bottom Actions Bar
            HStack {
                Button {
                    openWindow(id: "doctor")
                    NSApp.activate(ignoringOtherApps: true)
                } label: {
                    Label("Diagnostics", systemImage: "stethoscope")
                }
                .buttonStyle(.plain)
                .font(.caption)

                Spacer()

                Button {
                    model.refresh()
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .buttonStyle(.plain)
                .disabled(model.isBusy)

                Button {
                    NSApp.terminate(nil)
                } label: {
                    Image(systemName: "power")
                }
                .buttonStyle(.plain)
            }
            .padding(.horizontal, 16)
            .padding(.bottom, 12)
        }
        .onAppear {
            model.refresh()
        }
    }

    private var statusColor: Color {
        if model.killSwitchEnabled == true { return .green }
        if model.killSwitchEnabled == nil { return .orange }
        if model.report?.tunnelUp == false { return .orange }
        return .blue
    }

    private func verdictColor(_ v: PathExplanation.Verdict) -> Color {
        switch v {
        case .viaTunnel, .direct, .loopback:
            return .green
        case .blocked, .dnsFailure, .noRoute:
            return .red
        }
    }
}

// MARK: - Doctor Diagnostics Window

struct DoctorWindowView: View {
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(spacing: 16) {
            // Top Toolbar
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("RouteClue Diagnostics")
                        .font(.title2.bold())
                    Text("Verified system routing, split DNS, and leak-protection state")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()

                Button("Heal All") {
                    model.healAll()
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.isBusy || model.configError != nil)

                Button("Refresh") {
                    model.refresh()
                }
                .disabled(model.isBusy)
            }

            // Cards Grid
            ScrollView {
                VStack(spacing: 12) {
                    // Interfaces Card
                    DiagnosticCard(title: "Network Interfaces", icon: "network") {
                        VStack(alignment: .leading, spacing: 6) {
                            DetailRow(label: "Physical LAN", value: "\(model.report?.lanInterface ?? "none") (\(model.report?.lanAddress ?? "—"))")
                            DetailRow(label: "LAN Gateway", value: model.report?.gateway ?? "none")
                            DetailRow(label: "Default Route", value: model.report?.defaultInterface ?? "none")
                            DetailRow(label: "VPN Tunnel", value: "\(model.report?.tunnelInterface ?? "none") (\(model.report?.tunnelUp == true ? "ACTIVE" : "DOWN"))")
                            DetailRow(label: "External IP", value: model.report?.exitIP ?? "unknown")
                        }
                    }

                    // Routes Card
                    DiagnosticCard(title: "Corporate Subnet Routes", icon: "arrow.triangle.branch") {
                        VStack(alignment: .leading, spacing: 6) {
                            if let routes = model.report?.routes, !routes.isEmpty {
                                ForEach(routes, id: \.subnet) { r in
                                    HStack {
                                        Text(r.subnet)
                                            .font(.system(.caption, design: .monospaced))
                                        Spacer()
                                        Text(r.gateway ?? "missing")
                                            .font(.system(.caption, design: .monospaced))
                                            .foregroundStyle(.secondary)
                                        Text(r.isOK ? "✔ ifscope" : "✖ \(r.gateway == nil ? "missing" : "no ifscope")")
                                            .font(.caption2.bold())
                                            .foregroundStyle(r.isOK ? Color.green : Color.red)
                                    }
                                }
                            } else {
                                Text("No subnets configured.")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }

                    // DNS Zones Card
                    DiagnosticCard(title: "Split DNS Resolvers (/etc/resolver)", icon: "globe") {
                        VStack(alignment: .leading, spacing: 6) {
                            if let zones = model.report?.zones, !zones.isEmpty {
                                ForEach(zones, id: \.zone) { z in
                                    HStack {
                                        Text(z.zone)
                                            .font(.caption.bold())
                                        Spacer()
                                        Text(z.serverAlive ? "✔ Answers" : "✖ Silent")
                                            .font(.caption2)
                                            .foregroundStyle(z.serverAlive ? Color.green : Color.red)
                                    }
                                }
                            } else {
                                Text("No DNS zones active.")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }

                    // Raw Summary
                    DiagnosticCard(title: "System Log Output", icon: "terminal") {
                        Text(model.report?.summary ?? "Collecting state…")
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .padding(.vertical, 4)
            }

            if let msg = model.lastMessage {
                Text(msg)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(18)
    }
}

struct DiagnosticCard<Content: View>: View {
    let title: String
    let icon: String
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(title, systemImage: icon)
                .font(.headline)
            content()
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }
}

struct DetailRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .font(.system(.caption, design: .monospaced))
        }
    }
}
