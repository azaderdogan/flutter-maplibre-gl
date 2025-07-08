import Foundation
import MapLibre

// A custom URLProtocol to intercept all MapLibre network requests and inject headers.
class HeaderAddingURLProtocol: URLProtocol {
    private var dataTask: URLSessionDataTask?
    // A key to mark requests that this protocol has already handled, to prevent infinite loops.
    private static let handledKey = "HeaderAddingURLProtocolHandledKey"

    override class func canInit(with request: URLRequest) -> Bool {
        // 1. If we've already handled this request, don't handle it again.
        if URLProtocol.property(forKey: handledKey, in: request) != nil {
            return false
        }
        
        // 2. Only intercept http and https requests.
        guard let scheme = request.url?.scheme, ["http", "https"].contains(scheme) else {
            return false
        }
        
        return true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        // This method is required, but we don't need to modify the request here.
        return request
    }

    override func startLoading() {
        // Create a mutable copy of the original request.
        guard let mutableRequest = (request as NSURLRequest).mutableCopy() as? NSMutableURLRequest else {
            let error = NSError(domain: NSURLErrorDomain, code: URLError.Code.unknown.rawValue, userInfo: nil)
            client?.urlProtocol(self, didFailWithError: error)
            return
        }

        // Mark this request as handled to prevent re-entering the protocol.
        URLProtocol.setProperty(true, forKey: HeaderAddingURLProtocol.handledKey, in: mutableRequest)

        // Get the current headers from our singleton and add them to the request.
        let headers = NetworkConfiguration.shared.getCurrentHeaders()
        for (key, value) in headers {
            mutableRequest.setValue(value, forHTTPHeaderField: key)
        }

        // Create a new URLSession to perform the actual network request.
        // We use a default configuration because we've already added the headers.
        let session = URLSession(configuration: .default)
        dataTask = session.dataTask(with: mutableRequest as URLRequest) { [weak self] data, response, error in
            guard let self = self else { return }

            if let error = error {
                self.client?.urlProtocol(self, didFailWithError: error)
                return
            }
            if let response = response {
                self.client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            }
            if let data = data {
                self.client?.urlProtocol(self, didLoad: data)
            }
            self.client?.urlProtocolDidFinishLoading(self)
        }
        dataTask?.resume()
    }

    override func stopLoading() {
        // This is called if the request is cancelled or completes.
        dataTask?.cancel()
        dataTask = nil
    }
}

/// Handles network configuration for MapLibre, including SSL certificate validation
class NetworkConfiguration {
    /// Singleton instance
    static let shared = NetworkConfiguration()
    
    private init() {
        // Register our custom protocol when the app starts.
        // This only needs to be done once.
        URLProtocol.registerClass(HeaderAddingURLProtocol.self)
    }
    
    // Store current headers
    private var currentHeaders: [String: String] = [:]

    // Store SSL bypass state
    private var isSSLValidationBypassed = false

    // Public getter for the URLProtocol to access the headers.
    func getCurrentHeaders() -> [String: String] {
        return currentHeaders
    }
    
    /// Configures SSL certificate validation
    /// - Parameter enabled: When true, SSL certificate validation is bypassed
    func configureSSLValidation(enabled: Bool) {
        isSSLValidationBypassed = enabled
        updateNetworkConfiguration()
    }
    
    /// Configures HTTP headers for all requests
    /// - Parameter headers: Dictionary of HTTP headers to be added to all requests
    func configureHeaders(_ headers: [String: String]) {
        currentHeaders.merge(headers, uniquingKeysWith: { $1 })
        updateNetworkConfiguration()
    }
    
    /// Updates network configuration while maintaining both SSL bypass state and headers
    private func updateNetworkConfiguration() {
        let sessionConfig = URLSessionConfiguration.default
        
        // While the URLProtocol handles header injection, setting it here as well provides a fallback
        // and is good practice. The protocol will overwrite it if necessary.
        sessionConfig.httpAdditionalHeaders = currentHeaders
        
        // This is the crucial part: we tell the session configuration to USE our custom protocol.
        // Note: The custom protocol is already registered globally in init(). This step ensures
        // that the session configuration created here is explicitly aware of it.
        var protocolClasses = sessionConfig.protocolClasses ?? []
        if !protocolClasses.contains(where: { $0 == HeaderAddingURLProtocol.self }) {
            protocolClasses.insert(HeaderAddingURLProtocol.self, at: 0)
        }
        sessionConfig.protocolClasses = protocolClasses
        
        if isSSLValidationBypassed {
            // Create a URLSession with SSL bypass delegate
            let session = URLSession(
                configuration: sessionConfig,
                delegate: SSLBypassDelegate.shared,
                delegateQueue: nil
            )
            
            // Store the session in a static property to prevent it from being deallocated
            NetworkConfiguration.sslBypassSession = session
        } else {
            // Reset to default configuration but keep headers
            NetworkConfiguration.sslBypassSession = nil
        }
        
        MLNNetworkConfiguration.sharedManager.sessionConfiguration = sessionConfig
    }
    
    // Keep a strong reference to the SSL bypass session
    private static var sslBypassSession: URLSession?
}

/// URLSessionDelegate that handles SSL certificate validation
private class SSLBypassDelegate: NSObject, URLSessionDelegate {
    static let shared = SSLBypassDelegate()
    
    private override init() {
        super.init()
    }
    
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let serverTrust = challenge.protectionSpace.serverTrust {
            let credential = URLCredential(trust: serverTrust)
            completionHandler(.useCredential, credential)
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
} 