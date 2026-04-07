import { Severity } from "./rules.js";
export interface Finding {
    ruleId: string;
    ruleName: string;
    severity: Severity;
    category: string;
    message: string;
    file: string;
    line: number;
    snippet: string;
}
export interface AuditReport {
    timestamp: string;
    projectPath: string;
    totalFiles: number;
    findings: Finding[];
    summary: Record<Severity, number>;
    categories: Record<string, number>;
}
/** Run full audit on a project directory */
export declare function audit(projectDir: string, options?: {
    categories?: string[];
    severity?: Severity[];
}): AuditReport;
/** Format report as human-readable text */
export declare function formatReport(report: AuditReport): string;
