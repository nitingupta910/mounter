import ArgumentParser
import Foundation

private let IMAGE = "mounter-sshfs"
private let CONTAINER = "mounter"

@main
struct Mounter: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "mounter",
        abstract: "Mount remote directories over SSH — visible in Finder",
        discussion: """
            Runs a lightweight Docker container (via OrbStack) with the latest
            sshfs built from source. Remote files are exported to macOS over SMB.

            No macFUSE, no kernel extensions, no sudo required.
            Requires: OrbStack with Docker (https://orbstack.dev)
            """,
        version: "0.4.0",
        subcommands: [MountCmd.self, UnmountCmd.self, ListCmd.self, StatusCmd.self]
    )
}

// MARK: - Mount

struct MountCmd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "mount")

    @Argument(help: "[user@]host:[/path]")
    var remote: String

    @Option(name: .shortAndLong, help: "SSH port")
    var port: Int = 22

    @Option(name: .shortAndLong, help: "SSH identity file")
    var identity: String?

    @Option(name: .shortAndLong, help: "Mount name (default: host)")
    var name: String?

    func run() async throws {
        try Docker.requireInstalled()

        let parsed = try RemotePath.parse(remote)
        let resolved = try SSHConfig.resolve(host: parsed.host)
        let mountName = name ?? parsed.host
        let sshUser = parsed.user ?? resolved.user
        let sshPort = port != 22 ? port : resolved.port
        let resolvedHost = resolveHost(resolved.hostname)

        // Find SSH key
        let keyPath = identity.map { NSString(string: $0).expandingTildeInPath }
            ?? resolved.identityFile
        guard let keyPath = keyPath else {
            throw Err.msg("No SSH key found. Use --identity or set up ~/.ssh/id_*")
        }

        print("Mounting \(parsed.display)...")

        // 1. Build image + start container (first time ~2 min, then cached)
        try Docker.ensureRunning()

        // 2. Copy SSH key into the container
        let containerKey = "/root/.ssh/key-\(mountName)"
        try Docker.copyFile(from: keyPath, to: containerKey)
        try Docker.exec("chmod 600 \(containerKey)")

        // 3. sshfs mount inside the container
        let vmMount = "/mnt/\(mountName)"
        let alreadyMounted = (try? Docker.execOutput(
            "mountpoint -q \(vmMount) 2>/dev/null && echo y || echo n"
        ))?.trimmingCharacters(in: .whitespacesAndNewlines) == "y"

        if alreadyMounted {
            print("Already mounted in container.")
        } else {
            try Docker.exec("mkdir -p \(vmMount)")
            var cmd = "sshfs"
            cmd += " -o StrictHostKeyChecking=accept-new"
            cmd += " -o reconnect"
            cmd += " -o ServerAliveInterval=15"
            cmd += " -o ServerAliveCountMax=3"
            cmd += " -o allow_other"
            cmd += " -o IdentityFile=\(containerKey)"
            if sshPort != 22 { cmd += " -o port=\(sshPort)" }
            cmd += " \(sshUser)@\(resolvedHost):\(parsed.path) \(vmMount)"
            try Docker.exec(cmd)
        }

        // 4. Add Samba share
        try Docker.addSambaShare(name: mountName, path: vmMount)

        // 5. Mount SMB on macOS (no sudo)
        let containerIP = try Docker.containerIP()
        let macMount = NSString(string: "~/mnt/\(mountName)").expandingTildeInPath
        try FileManager.default.createDirectory(atPath: macMount, withIntermediateDirectories: true)

        // Unmount stale
        if isMacMounted(macMount) { shell("/sbin/umount", macMount) }

        let r = shell("/sbin/mount_smbfs", "//guest@\(containerIP)/\(mountName)", macMount)
        guard r.status == 0 else {
            throw Err.msg("SMB mount failed: \(r.output)")
        }

        print("Mounted at \(macMount)")
        print("Open in Finder:  open \(macMount)")
    }
}

// MARK: - Unmount

struct UnmountCmd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "unmount")

    @Argument(help: "Mount name or path")
    var target: String

    func run() async throws {
        let mountName = target.hasPrefix("/")
            ? (target as NSString).lastPathComponent : target
        let macMount = NSString(string: "~/mnt/\(mountName)").expandingTildeInPath

        if isMacMounted(macMount) {
            shell("/sbin/umount", macMount)
            if isMacMounted(macMount) {
                shell("/usr/sbin/diskutil", "unmount", "force", macMount)
            }
            print("Unmounted \(macMount)")
        }

        if Docker.isRunning() {
            try? Docker.exec("fusermount3 -u /mnt/\(mountName) 2>/dev/null || fusermount -u /mnt/\(mountName) 2>/dev/null")
            try? Docker.removeSambaShare(name: mountName)
        }
        print("Done.")
    }
}

// MARK: - List

struct ListCmd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "list")

    func run() async throws {
        guard Docker.isRunning() else {
            print("No active mounts")
            return
        }

        let mounts = (try? Docker.execOutput(
            "mount -t fuse.sshfs 2>/dev/null"
        )) ?? ""

        if mounts.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            print("No active mounts")
            return
        }

        for line in mounts.split(separator: "\n") {
            let parts = line.split(separator: " ", maxSplits: 5)
            guard parts.count >= 3 else { continue }
            let remote = String(parts[0])
            let name = (String(parts[2]) as NSString).lastPathComponent
            let macPath = NSString(string: "~/mnt/\(name)").expandingTildeInPath
            let macOK = isMacMounted(macPath)

            print("  \(name)")
            print("    Remote:  \(remote)")
            print("    Finder:  \(macPath) [\(macOK ? "mounted" : "stale — run: mounter mount \(name)")]")
            print()
        }
    }
}

// MARK: - Status

struct StatusCmd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "status")

    func run() async throws {
        let running = Docker.isRunning()
        print("Container: \(running ? "running" : "stopped")")
        if running {
            let sshfsVersion = (try? Docker.execOutput("sshfs --version 2>&1"))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "?"
            print("sshfs:     \(sshfsVersion)")
            let mounts = (try? Docker.execOutput("mount -t fuse.sshfs 2>/dev/null")) ?? ""
            let count = mounts.split(separator: "\n").count
            print("Mounts:    \(count > 0 ? "\(count) active" : "none")")
        }
    }
}

// MARK: - Docker management

enum Docker {
    static func requireInstalled() throws {
        guard shell("/usr/bin/which", "docker").status == 0 else {
            throw Err.msg("Docker not found. Install OrbStack: https://orbstack.dev")
        }
    }

    static func isRunning() -> Bool {
        shell("docker", "inspect", "-f", "{{.State.Running}}", CONTAINER)
            .output.contains("true")
    }

    static func ensureRunning() throws {
        if isRunning() { return }

        // Build image if needed
        let imageExists = shell("docker", "image", "inspect", IMAGE).status == 0
        if !imageExists {
            print("Building sshfs image (one-time, ~2 min)...")
            let projectDir = findProjectDir()
            let r = shell("docker", "build", "-t", IMAGE, projectDir)
            guard r.status == 0 else {
                throw Err.msg("Docker build failed:\n\(r.output)")
            }
            print("Image built.")
        }

        // Start or create container
        let exists = shell("docker", "inspect", CONTAINER).status == 0
        if exists {
            let r = shell("docker", "start", CONTAINER)
            guard r.status == 0 else { throw Err.msg("Container start failed: \(r.output)") }
        } else {
            let r = shell(
                "docker", "run", "-d",
                "--name", CONTAINER,
                "--privileged",
                "--restart", "unless-stopped",
                IMAGE
            )
            guard r.status == 0 else { throw Err.msg("Container create failed: \(r.output)") }
        }

        // Wait for samba to be ready
        for _ in 0..<10 {
            if (try? execOutput("service smbd status 2>/dev/null"))?.contains("running") == true {
                return
            }
            Thread.sleep(forTimeInterval: 0.5)
        }
    }

    static func exec(_ cmd: String) throws {
        let r = shell("docker", "exec", CONTAINER, "bash", "-c", cmd)
        guard r.status == 0 else {
            throw Err.msg("exec failed: \(r.output)")
        }
    }

    static func execOutput(_ cmd: String) throws -> String {
        shell("docker", "exec", CONTAINER, "bash", "-c", cmd).output
    }

    static func copyFile(from localPath: String, to containerPath: String) throws {
        let r = shell("docker", "cp", localPath, "\(CONTAINER):\(containerPath)")
        guard r.status == 0 else {
            throw Err.msg("docker cp failed: \(r.output)")
        }
    }

    static func containerIP() throws -> String {
        let r = shell("docker", "inspect", "-f",
                       "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                       CONTAINER)
        let ip = r.output.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !ip.isEmpty else { throw Err.msg("Can't get container IP") }
        return ip
    }

    static func addSambaShare(name: String, path: String) throws {
        let exists = (try? execOutput(
            "grep -c '\\[\(name)\\]' /etc/samba/smb.conf 2>/dev/null"
        ))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "0"

        if exists == "0" {
            let block = [
                "", "[\(name)]", "path = \(path)",
                "browseable = yes", "read only = no",
                "guest ok = yes", "force user = root",
                "create mask = 0644", "directory mask = 0755"
            ].joined(separator: "\n")
            try exec("printf '%s\\n' \(block.shellEscaped) >> /etc/samba/smb.conf")
        }
        try exec("service smbd reload 2>/dev/null || service smbd restart")
    }

    static func removeSambaShare(name: String) throws {
        try exec("sed -i '/^\\[\(name)\\]$/,/^$/d' /etc/samba/smb.conf")
        try exec("service smbd reload 2>/dev/null || service smbd restart")
    }

    static func findProjectDir() -> String {
        // Find Dockerfile relative to the binary or current directory
        let candidates = [
            Bundle.main.bundlePath + "/../../../",  // .build/debug/mounter → project root
            FileManager.default.currentDirectoryPath,
        ]
        for dir in candidates {
            let path = (dir as NSString).appendingPathComponent("Dockerfile")
            if FileManager.default.fileExists(atPath: path) {
                return dir
            }
        }
        return FileManager.default.currentDirectoryPath
    }
}

// MARK: - SSH Config

enum SSHConfig {
    struct Resolved {
        let hostname: String
        let user: String
        let port: Int
        let identityFile: String?
    }

    static func resolve(host: String) throws -> Resolved {
        let r = shell("/usr/bin/ssh", "-G", host)
        guard r.status == 0 else { throw Err.msg("Can't resolve SSH config for \(host)") }

        var hostname = host, user = NSUserName(), port = 22
        var identityFile: String?

        for line in r.output.split(separator: "\n") {
            let parts = line.split(separator: " ", maxSplits: 1)
            guard parts.count == 2 else { continue }
            switch String(parts[0]).lowercased() {
            case "hostname": hostname = String(parts[1])
            case "user": user = String(parts[1])
            case "port": port = Int(parts[1]) ?? 22
            case "identityfile":
                let p = NSString(string: String(parts[1])).expandingTildeInPath
                if identityFile == nil && FileManager.default.fileExists(atPath: p) {
                    identityFile = p
                }
            default: break
            }
        }
        return Resolved(hostname: hostname, user: user, port: port, identityFile: identityFile)
    }
}

// MARK: - Helpers

struct RemotePath {
    let user: String?, host: String, path: String
    var display: String { user.map { "\($0)@\(host):\(path)" } ?? "\(host):\(path)" }

    static func parse(_ spec: String) throws -> RemotePath {
        var rest = spec; var user: String?
        if let at = rest.firstIndex(of: "@") {
            user = String(rest[..<at]); rest = String(rest[rest.index(after: at)...])
        }
        guard let colon = rest.firstIndex(of: ":") else {
            guard !rest.isEmpty else { throw Err.msg("Bad remote: \(spec)") }
            return RemotePath(user: user, host: rest, path: "/")
        }
        let host = String(rest[..<colon])
        var path = String(rest[rest.index(after: colon)...]); if path.isEmpty { path = "/" }
        guard !host.isEmpty else { throw Err.msg("Bad remote: \(spec)") }
        return RemotePath(user: user, host: host, path: path)
    }
}

extension String {
    var shellEscaped: String { "'" + replacingOccurrences(of: "'", with: "'\\''") + "'" }
}

func resolveHost(_ hostname: String) -> String {
    let r = shell("/usr/bin/host", hostname)
    if r.status == 0, let line = r.output.split(separator: "\n").first,
       let ip = line.split(separator: " ").last { return String(ip) }
    return hostname
}

func isMacMounted(_ path: String) -> Bool {
    shell("/sbin/mount").output.contains(" on \(path) ")
}

@discardableResult
func shell(_ args: String...) -> (status: Int32, output: String) {
    let p = Process(); let pipe = Pipe()
    p.executableURL = URL(fileURLWithPath: args[0].hasPrefix("/") ? args[0] : "/usr/bin/env")
    p.arguments = args[0].hasPrefix("/") ? Array(args.dropFirst()) : args
    p.standardOutput = pipe; p.standardError = pipe
    do { try p.run() } catch { return (-1, "\(error)") }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return (p.terminationStatus, String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "")
}

enum Err: LocalizedError {
    case msg(String)
    var errorDescription: String? { if case .msg(let s) = self { return s } else { return nil } }
}
