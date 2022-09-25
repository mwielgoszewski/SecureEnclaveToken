//
//  AppDelegate.swift
//  SecureEnclaveToken
//
//  Created by Marcin Wielgoszewski on 2/11/21.
//

import Cocoa
import SwiftUI
import ArgumentParser

class AppDelegate: NSObject, NSApplicationDelegate {

    var window: NSWindow!

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        // arg.0 is the current executable
        let args = Array(CommandLine.arguments.dropFirst())

        // execute this as a cli app, then exit immediately
        if args.first == "cli" {
            SecureEnclaveTokenCLI.main(Array(args.dropFirst()))
            exit(0)
        }

        // Create the SwiftUI view that provides the window contents.
        let contentView = ContentView()

        // Create the window and set the content view.
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 480, height: 640),
            styleMask: [.titled, .closable, .miniaturizable, .fullSizeContentView],
            backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.center()
        window.setFrameAutosaveName("Main Window")
        window.contentView = NSHostingView(rootView: contentView)
        window.makeKeyAndOrderFront(nil)
    }

    func applicationWillTerminate(_ aNotification: Notification) {
        // Insert code here to tear down your application
    }

}
