#!/usr/bin/env node
import { audit, formatReport } from "./scanner.js";
const projectPath = process.argv[2] || process.cwd();
console.log(`\nScanning: ${projectPath}\n`);
const report = audit(projectPath);
console.log(formatReport(report));
process.exit(report.summary.critical > 0 ? 2 : report.summary.high > 0 ? 1 : 0);
