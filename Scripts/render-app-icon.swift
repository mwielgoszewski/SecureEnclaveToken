#!/usr/bin/env swift
// Run from the repository root. Export the native Icon Composer artwork for docs/web.
import Foundation

func run(_ executable: URL, _ arguments: [String]) throws -> String {
    let process = Process()
    process.executableURL = executable
    process.arguments = arguments
    let output = Pipe()
    process.standardOutput = output
    process.standardError = output
    try process.run()
    let data = output.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    let message = String(decoding: data, as: UTF8.self)
    guard process.terminationStatus == 0 else {
        throw NSError(domain: "IconExport", code: Int(process.terminationStatus),
                      userInfo: [NSLocalizedDescriptionKey: message])
    }
    return message
}

let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
let developer = try run(URL(fileURLWithPath: "/usr/bin/xcode-select"), ["-p"])
    .trimmingCharacters(in: .whitespacesAndNewlines)
let tool = URL(fileURLWithPath: developer).deletingLastPathComponent()
    .appendingPathComponent("Applications/Icon Composer.app/Contents/Executables/ictool")
let icon = root.appendingPathComponent("SecureEnclaveToken/AppIcon.icon")
let artwork = root.appendingPathComponent("docs/branding", isDirectory: true)
try FileManager.default.createDirectory(at: artwork, withIntermediateDirectories: true)
for (name, size) in [("app-icon.png", 1024), ("app-icon-preview.png", 256), ("favicon.png", 64)] {
    _ = try run(tool, [icon.path, "--export-image", "--output-file", artwork.appendingPathComponent(name).path,
                       "--platform", "macOS", "--rendition", "Default",
                       "--width", String(size), "--height", String(size), "--scale", "1"])
}
let webAssets = root.appendingPathComponent("website/dist/assets", isDirectory: true)
if FileManager.default.fileExists(atPath: webAssets.path) {
    for name in ["app-icon.png", "favicon.png"] {
        try Data(contentsOf: artwork.appendingPathComponent(name)).write(to: webAssets.appendingPathComponent(name), options: .atomic)
    }
}
print("Exported the native icon for documentation, website, and favicon.")
