//
//  main.swift
//  SecureEnclaveToken
//
//  Created by Marcin Wielgoszewski on 9/24/22.
//

import Foundation
import AppKit


let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate

// 2
_ = NSApplicationMain(CommandLine.argc, CommandLine.unsafeArgv)

