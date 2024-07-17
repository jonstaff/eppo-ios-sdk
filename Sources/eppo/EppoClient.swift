import Foundation;

// todo: make this a build argument (FF-1944)
public let sdkName = "ios"
public let sdkVersion = "3.0.1"

public enum Errors: Error {
    case notConfigured
    case sdkKeyInvalid
    case hostInvalid
    case subjectKeyRequired
    case flagKeyRequired
    case variationTypeMismatch
    case variationWrongType
    case invalidURL
    case configurationNotLoaded
    case flagConfigNotFound
}

public typealias SubjectAttributes = [String: EppoValue];
actor EppoClientState {
    private(set) var isLoaded: Bool = false
    
    func checkAndSetLoaded() -> Bool {
        if !isLoaded {
            isLoaded = true
            return false
        }
        return true
    }
}

public class EppoClient {
    public typealias AssignmentLogger = (Assignment) -> Void

    private var flagEvaluator: FlagEvaluator = FlagEvaluator(sharder: MD5Sharder())

    public var isConfigObfuscated = true

    private(set) var sdkKey: String
    private(set) var host: String
    private(set) var assignmentLogger: AssignmentLogger?
    private(set) var assignmentCache: AssignmentCache?
    private(set) var configurationStore: ConfigurationStore

    private let queue = DispatchQueue(label: "com.eppo.client.EppoClient", attributes: .concurrent)

    private var _hasLoaded = false
    private var hasLoaded: Bool {
        get {
            queue.sync {
                self._hasLoaded
            }
        }
        set {
            queue.async(flags: .barrier) {
                self._hasLoaded = newValue
            }
        }
    }

    public init(
        sdkKey: String,
        host: String = "https://fscdn.eppo.cloud",
        assignmentLogger: AssignmentLogger? = nil,
        assignmentCache: AssignmentCache? = InMemoryAssignmentCache()
    ) {
        self.sdkKey = sdkKey
        self.host = host
        self.assignmentLogger = assignmentLogger
        self.assignmentCache = assignmentCache

        let httpClient = NetworkEppoHttpClient(baseURL: host, sdkKey: sdkKey, sdkName: "sdkName", sdkVersion: sdkVersion)
        let configurationRequester = ConfigurationRequester(httpClient: httpClient)
        self.configurationStore = ConfigurationStore(requester: configurationRequester)
    }

    // Note: this *must* be called before getting any assignments, otherwise an error will
    // be thrown
    public func load(force: Bool = false) async throws {
        guard !hasLoaded || force else {
            return
        }

        // Prevent multiple subsequent calls, optimistically assuming the fetch will succeed
        hasLoaded = true

        do {
            try await configurationStore.fetchAndStoreConfigurations()
        } catch {
            hasLoaded = false
            throw error
        }
    }

    public func getAssignment(
        flagKey: String,
        subjectKey: String,
        subjectAttributes: SubjectAttributes = SubjectAttributes()) throws -> String?
    {
        return try getInternalAssignment(
            flagKey: flagKey,
            subjectKey: subjectKey,
            subjectAttributes: subjectAttributes
        )?.variation?.value.getStringValue()
    }

    public func getBooleanAssignment(
        flagKey: String,
        subjectKey: String,
        subjectAttributes: SubjectAttributes = SubjectAttributes(),
        defaultValue: Bool) throws -> Bool
    {
        return try getInternalAssignment(
            flagKey: flagKey,
            subjectKey: subjectKey,
            subjectAttributes: subjectAttributes,
            expectedVariationType: UFC_VariationType.boolean
        )?.variation?.value.getBoolValue() ?? defaultValue
    }

    public func getJSONStringAssignment(
        flagKey: String,
        subjectKey: String,
        subjectAttributes: SubjectAttributes,
        defaultValue: String) throws -> String
    {
        return try getInternalAssignment(
            flagKey: flagKey,
            subjectKey: subjectKey,
            subjectAttributes: subjectAttributes,
            expectedVariationType: UFC_VariationType.json
        )?.variation?.value.getStringValue() ?? defaultValue
    }

    public func getIntegerAssignment(
        flagKey: String,
        subjectKey: String,
        subjectAttributes: SubjectAttributes = SubjectAttributes(),
        defaultValue: Int) throws -> Int
    {
        let assignment = try getInternalAssignment(
            flagKey: flagKey,
            subjectKey: subjectKey,
            subjectAttributes: subjectAttributes,
            expectedVariationType: UFC_VariationType.integer
        )

        return Int(try assignment?.variation?.value.getDoubleValue() ?? Double(defaultValue))
    }

    public func getNumericAssignment(
        flagKey: String,
        subjectKey: String,
        subjectAttributes: SubjectAttributes = SubjectAttributes(),
        defaultValue: Double) throws -> Double
    {
        return try getInternalAssignment(
            flagKey: flagKey,
            subjectKey: subjectKey,
            subjectAttributes: subjectAttributes,
            expectedVariationType: UFC_VariationType.numeric
        )?.variation?.value.getDoubleValue() ?? defaultValue
    }

    public func getStringAssignment(
        flagKey: String,
        subjectKey: String,
        subjectAttributes: SubjectAttributes = SubjectAttributes(),
        defaultValue: String) throws -> String
    {
        return try getInternalAssignment(
            flagKey: flagKey,
            subjectKey: subjectKey,
            subjectAttributes: subjectAttributes,
            expectedVariationType: UFC_VariationType.string
        )?.variation?.value.getStringValue() ?? defaultValue
    }

    private func getInternalAssignment(
        flagKey: String,
        subjectKey: String,
        subjectAttributes: SubjectAttributes,
        expectedVariationType: UFC_VariationType? = nil) throws -> FlagEvaluation?
    {
        guard hasLoaded else {
            throw Errors.configurationNotLoaded
        }

        guard !sdkKey.isEmpty else {
            throw Errors.sdkKeyInvalid
        }

        guard !host.isEmpty else {
            throw Errors.hostInvalid
        }

        guard !subjectKey.isEmpty else {
            throw Errors.subjectKeyRequired
        }

        guard !flagKey.isEmpty else {
            throw Errors.flagKeyRequired
        }

        let flagKeyForLookup = isConfigObfuscated ? getMD5Hex(flagKey) : flagKey

        guard let flagConfig = self.configurationStore.getConfiguration(flagKey: flagKeyForLookup) else {
            throw Errors.flagConfigNotFound
        }

        if let expectedVariationType, flagConfig.variationType != expectedVariationType {
            throw Errors.variationTypeMismatch
        }

        let flagEvaluation = flagEvaluator.evaluateFlag(
            flag: flagConfig,
            subjectKey: subjectKey,
            subjectAttributes: subjectAttributes,
            isConfigObfuscated: isConfigObfuscated
        )

        if let variation = flagEvaluation.variation, let expectedVariationType, !variation.value.isOfType(expectedVariationType) {
            throw Errors.variationWrongType
        }

        // Optionally log assignment
        if flagEvaluation.doLog {
            if let assignmentLogger {
                let allocationKey = flagEvaluation.allocationKey ?? "__eppo_no_allocation"
                let variationKey = flagEvaluation.variation?.key ?? "__eppo_no_variation"

                // Prepare the assignment cache key
                let assignmentCacheKey = AssignmentCacheKey(
                    subjectKey: subjectKey,
                    flagKey: flagKey,
                    allocationKey: allocationKey,
                    variationKey: variationKey
                )

                // Check if the assignment has already been logged, if the cache is defined
                if let cache = self.assignmentCache, cache.hasLoggedAssignment(key: assignmentCacheKey) {
                    // The assignment has already been logged, do nothing
                } else {
                    // Either the cache is not defined, or the assignment hasn't been logged yet
                    // Perform assignment.
                    let assignment = Assignment(
                        flagKey: flagKey,
                        allocationKey: allocationKey,
                        variation: variationKey,
                        subject: subjectKey,
                        timestamp: ISO8601DateFormatter().string(from: Date()),
                        subjectAttributes: subjectAttributes,
                        metaData: [
                            "obfuscated": String(isConfigObfuscated),
                            "sdkName": sdkName,
                            "sdkVersion": sdkVersion
                        ],
                        extraLogging: flagEvaluation.extraLogging
                    )

                    assignmentLogger(assignment)
                    self.assignmentCache?.setLastLoggedAssignment(key: assignmentCacheKey)
                }
            }
        }

        return flagEvaluation
    }
}

private extension EppoValue {
    func isOfType(_ expectedType: UFC_VariationType) -> Bool {
        switch expectedType {
        case .json, .string:
            return self.isString()
        case .integer:
            let doubleValue = try? self.getDoubleValue()
            return self.isNumeric() && doubleValue != nil && floor(doubleValue!) == doubleValue!
        case .numeric:
            return self.isNumeric()
        case .boolean:
            return self.isBool()
        }
    }
}
