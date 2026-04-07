export type Severity = "critical" | "high" | "medium" | "low" | "info";
export interface Rule {
    id: string;
    name: string;
    description: string;
    severity: Severity;
    category: string;
    /** File glob patterns to scan */
    filePatterns: string[];
    /** Regex patterns that indicate a vulnerability */
    badPatterns?: {
        pattern: RegExp;
        message: string;
    }[];
    /** Regex patterns that SHOULD exist — absence is the finding */
    requiredPatterns?: {
        pattern: RegExp;
        message: string;
        filePattern: string;
    }[];
}
export declare const e2eRules: Rule[];
export declare const webrtcRules: Rule[];
export declare const messengerRules: Rule[];
export declare const androidRules: Rule[];
export declare const backendRules: Rule[];
export declare const allRules: Rule[];
