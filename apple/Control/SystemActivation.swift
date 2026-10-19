import Foundation
import SystemExtensions

final class SystemActivation: NSObject, OSSystemExtensionRequestDelegate {
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .replace }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) { print("Approve Bimeron Core in macOS Privacy & Security settings") }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        print(result == .completed ? "System extension request completed" : "System extension change pending reboot"); exit(0)
    }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) { fail("system extension request failed; check signing, provisioning and /Applications location") }
}
