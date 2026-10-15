import Foundation

final class Router {
    static let shared = Router()

    func handle(_ url: URL) -> Bool {
        return url.pathComponents.count > 1
    }
}
