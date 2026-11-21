import AppKit
import SwiftUI

let arguments = Array(CommandLine.arguments.dropFirst())
if arguments.first == "cli" {
    SecureEnclaveTokenCLI.main(Array(arguments.dropFirst()))
} else {
    SecureEnclaveTokenApp.main()
}
