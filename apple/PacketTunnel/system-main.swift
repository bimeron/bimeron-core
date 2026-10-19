import Foundation
import NetworkExtension

@main
struct BimeronSystemExtension {
    static func main() {
        autoreleasepool { NEProvider.startSystemExtensionMode() }
        dispatchMain()
    }
}
