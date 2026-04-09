// sentinel-kb-ignore-file
// Security audit rules for messenger applications

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
  badPatterns?: { pattern: RegExp; message: string }[];
  /** Regex patterns that SHOULD exist — absence is the finding */
  requiredPatterns?: { pattern: RegExp; message: string; filePattern: string }[];
}

// ─── E2E Encryption ─────────────────────────────────────────────

export const e2eRules: Rule[] = [
  {
    id: "E2E-001",
    name: "Plaintext logging of keys or secrets",
    description: "Logging private keys, session state, or decrypted content leaks secrets to logcat/disk",
    severity: "critical",
    category: "E2E Encryption",
    filePatterns: ["**/*.kt", "**/*.java", "**/*.rs"],
    badPatterns: [
      { pattern: /Log\.[diwev]\(.*(?:private[Kk]ey|secret[Kk]ey|sessionJson|decrypted[Mm]sg|plaintext[Mm]sg|\.password)\s*[,)$]/, message: "Logging sensitive data (key/secret/decrypted content)" },
      { pattern: /Log\.[diwev]\(.*\$\{.*(?:accessToken|refreshToken|privateKey|secretKey|password|sessionJson)\}/, message: "Logging secret value via string interpolation" },
      { pattern: /println!\(.*(?:private_key|secret_key|session_json|decrypted|plaintext|\.password)/, message: "Rust: printing sensitive data" },
      { pattern: /tracing::(?:info|debug|warn)\!.*(?:private_key|secret_key|\.password)/, message: "Rust: tracing sensitive data" },
    ],
  },
  {
    id: "E2E-002",
    name: "Hardcoded encryption key",
    description: "Encryption keys must never be hardcoded in source",
    severity: "critical",
    category: "E2E Encryption",
    filePatterns: ["**/*.kt", "**/*.java", "**/*.rs", "**/*.ts", "**/*.js"],
    badPatterns: [
      { pattern: /(?:aes|encryption|cipher|secret)_?[Kk]ey\s*=\s*"[A-Za-z0-9+/=]{16,}"/, message: "Hardcoded encryption key" },
      { pattern: /(?:val|var|let|const)\s+\w*[Ss]ecret\w*\s*=\s*"[^"]{8,}"/, message: "Hardcoded secret value" },
    ],
  },
  {
    id: "E2E-003",
    name: "Ratchet state not persisted atomically",
    description: "If ratchet state save fails after encrypt/decrypt, messages become unrecoverable",
    severity: "high",
    category: "E2E Encryption",
    filePatterns: ["**/*Repository*.kt", "**/*Manager*.kt", "**/*Service*.kt", "**/*ViewModel*.kt"],
    badPatterns: [
      { pattern: /ratchetEncrypt\([\s\S]{0,200}(?!withSessionLock|synchronized|mutex)/, message: "Encrypt without session lock — ratchet state may desync" },
      { pattern: /ratchetDecrypt\([\s\S]{0,200}(?!withSessionLock|synchronized|mutex)/, message: "Decrypt without session lock — ratchet state may desync" },
    ],
  },
  {
    id: "E2E-004",
    name: "Missing sender verification",
    description: "Incoming messages must verify sender identity to prevent impersonation",
    severity: "high",
    category: "E2E Encryption",
    filePatterns: ["**/*Repository*.kt", "**/*Manager*.kt", "**/*Service*.kt"],
    badPatterns: [
      { pattern: /ratchetDecrypt\([\s\S]{0,500}(?!verifySender|senderHint|identityKey)/, message: "Decrypt without sender verification" },
    ],
  },
  {
    id: "E2E-005",
    name: "OPK not replenished",
    description: "One-time prekeys must be replenished after use to maintain forward secrecy",
    severity: "medium",
    category: "E2E Encryption",
    filePatterns: ["**/*.kt", "**/*.java"],
    requiredPatterns: [
      { pattern: /replenish|uploadPrekeys|prekey.*upload|refill.*opk/i, message: "No OPK replenishment logic found", filePattern: "**/*Prekey*" },
    ],
  },
  {
    id: "E2E-006",
    name: "Non-constant-time comparison for crypto values",
    description: "Comparing MACs, hashes, or tokens with == allows timing attacks",
    severity: "high",
    category: "E2E Encryption",
    filePatterns: ["**/*.kt", "**/*.java"],
    badPatterns: [
      { pattern: /(?:mac|hmac|hash|digest|signature|token)\w*\s*==\s*\w*(?:mac|hmac|hash|digest|signature|token)/i, message: "Non-constant-time comparison of crypto values — use MessageDigest.isEqual()" },
    ],
  },
];

// ─── WebRTC / P2P ───────────────────────────────────────────────

export const webrtcRules: Rule[] = [
  {
    id: "P2P-001",
    name: "TURN credentials in source code",
    description: "TURN server credentials must not be hardcoded",
    severity: "critical",
    category: "WebRTC/P2P",
    filePatterns: ["**/*.kt", "**/*.java", "**/*.rs", "**/*.ts", "**/*.json"],
    badPatterns: [
      { pattern: /(?:turn|stun):[^\s]*@[^\s]*/, message: "TURN/STUN URI with embedded credentials" },
      { pattern: /(?:credential|password)\s*[:=]\s*"[^"]{8,}"[\s\S]{0,100}(?:turn|stun|ice)/i, message: "Hardcoded TURN credential near ICE config" },
    ],
  },
  {
    id: "P2P-002",
    name: "ICE candidate leaks local IP",
    description: "Local/mDNS ICE candidates can leak private network topology",
    severity: "medium",
    category: "WebRTC/P2P",
    filePatterns: ["**/*.kt", "**/*.java"],
    badPatterns: [
      { pattern: /onIceCandidate[\s\S]{0,300}(?!filter|mDNS|mdns|strip|sanitize).*send/, message: "ICE candidates sent without filtering — may leak local IPs" },
    ],
  },
  {
    id: "P2P-003",
    name: "DataChannel without authentication",
    description: "DataChannel messages must be authenticated to prevent injection by TURN operator",
    severity: "high",
    category: "WebRTC/P2P",
    filePatterns: ["**/*.kt", "**/*.java"],
    badPatterns: [
      { pattern: /onMessage[\s\S]{0,200}(?:getString|payload|text)[\s\S]{0,200}(?!verify|authenticate|decrypt|ratchet)/, message: "DataChannel message processed without authentication/decryption" },
    ],
  },
  {
    id: "P2P-004",
    name: "WebRTC logging exposes SDP",
    description: "Logging SDP offers/answers can expose ICE credentials and network topology",
    severity: "medium",
    category: "WebRTC/P2P",
    filePatterns: ["**/*.kt", "**/*.java"],
    badPatterns: [
      { pattern: /Log\.[diwev]\(.*(?:sdp|SDP|description|offer|answer)[\s\S]{0,50}\.description/, message: "Logging SDP content — exposes ICE credentials" },
    ],
  },
  {
    id: "P2P-005",
    name: "No SRTP for voice/video",
    description: "WebRTC media must use SRTP encryption — disabling it exposes audio/video",
    severity: "critical",
    category: "WebRTC/P2P",
    filePatterns: ["**/*.kt", "**/*.java"],
    badPatterns: [
      { pattern: /srtp.*disable|encryption.*false|RtpTransceiver.*unencrypt/i, message: "SRTP encryption disabled for media" },
    ],
  },
  {
    id: "P2P-006",
    name: "TURN static-auth-secret in code",
    description: "TURN shared secret must come from secure config, not source code",
    severity: "critical",
    category: "WebRTC/P2P",
    filePatterns: ["**/*.kt", "**/*.java", "**/*.rs", "**/*.env"],
    badPatterns: [
      { pattern: /static.auth.secret\s*[:=]\s*["\w]{16,}/, message: "TURN static-auth-secret hardcoded" },
    ],
  },
];

// ─── Messenger-Specific ─────────────────────────────────────────

export const messengerRules: Rule[] = [
  {
    id: "MSG-001",
    name: "Notification leaks message content",
    description: "Push notifications must not contain plaintext message content or sender name when privacy is enabled",
    severity: "high",
    category: "Messenger",
    filePatterns: ["**/*.kt", "**/*.java"],
    badPatterns: [
      { pattern: /setContentText\(.*(?:content|body|message|text)(?!.*notificationPrivacy|.*privacy)/, message: "Notification may leak message content" },
    ],
  },
  {
    id: "MSG-002",
    name: "Delivery receipt reveals sender",
    description: "Delivery/read receipts sent via server can reveal who sent messages (breaks sealed sender)",
    severity: "high",
    category: "Messenger",
    filePatterns: ["**/*.kt", "**/*.java"],
    badPatterns: [
      { pattern: /(?:delivered|read|seen|receipt)[\s\S]{0,300}sendToServer(?!.*sealedSender|.*deliveryToken)/, message: "Delivery receipt sent via server may break sealed sender" },
    ],
  },
  {
    id: "MSG-003",
    name: "Self-destruct message persisted after expiry",
    description: "Self-destructing messages must be deleted after TTL — not just hidden in UI",
    severity: "medium",
    category: "Messenger",
    filePatterns: ["**/*.kt", "**/*.java"],
    badPatterns: [
      { pattern: /self_?[Dd]estruct[\s\S]{0,500}(?:visibility|GONE|INVISIBLE)(?!.*delete|.*remove|.*dao)/, message: "Self-destruct message hidden but not deleted from DB" },
    ],
  },
  {
    id: "MSG-004",
    name: "Panic PIN does not wipe crypto keys",
    description: "Panic PIN must wipe private keys, session state, and DB — not just clear UI",
    severity: "high",
    category: "Messenger",
    filePatterns: ["**/*.kt", "**/*.java"],
    badPatterns: [
      { pattern: /panic[Pp]in[\s\S]{0,500}(?:finish|navigate|clear)(?![\s\S]{0,200}(?:wipe|delete|destroy|removeAll))/, message: "Panic PIN handler may not fully wipe crypto material" },
    ],
  },
  {
    id: "MSG-005",
    name: "Server stores sender_id for sealed messages",
    description: "Sealed sender messages must not store sender identity on server",
    severity: "critical",
    category: "Messenger",
    filePatterns: ["**/*.rs", "**/*.ts", "**/*.js"],
    badPatterns: [
      { pattern: /is_sealed.*true[\s\S]{0,200}sender_id\s*[:=]\s*(?!None|null|nil|undefined)/, message: "Sealed message stores sender_id on server" },
    ],
  },
  {
    id: "MSG-006",
    name: "Group messages not E2E encrypted per-member",
    description: "Group messages must be encrypted individually per member — shared key is weaker",
    severity: "medium",
    category: "Messenger",
    filePatterns: ["**/*.kt", "**/*.java"],
    badPatterns: [
      { pattern: /group.*encrypt[\s\S]{0,200}(?:shared[Kk]ey|group[Kk]ey)(?!.*perMember|.*individual)/, message: "Group messages using shared key instead of per-member encryption" },
    ],
  },
  {
    id: "MSG-007",
    name: "Message content in server logs",
    description: "Server must never log message content, even encrypted ciphertext (traffic analysis)",
    severity: "high",
    category: "Messenger",
    filePatterns: ["**/*.rs"],
    badPatterns: [
      { pattern: /tracing::(?:info|debug)\!.*(?:ciphertext|message_ciphertext|content|body|payload)/, message: "Server logs message content/ciphertext" },
      { pattern: /println!\(.*(?:ciphertext|message|content|body)/, message: "Server prints message content" },
    ],
  },
];

// ─── Android Security ───────────────────────────────────────────

export const androidRules: Rule[] = [
  {
    id: "AND-001",
    name: "Exported component without permission",
    description: "Exported activities/services/receivers must require permissions to prevent unauthorized access",
    severity: "high",
    category: "Android",
    filePatterns: ["**/AndroidManifest.xml"],
    badPatterns: [
      { pattern: /android:exported="true"(?![\s\S]{0,200}android:permission)/, message: "Exported component without permission requirement" },
    ],
  },
  {
    id: "AND-002",
    name: "Cleartext traffic allowed",
    description: "App must enforce HTTPS — cleartext HTTP allows MITM",
    severity: "high",
    category: "Android",
    filePatterns: ["**/AndroidManifest.xml", "**/network_security_config.xml"],
    badPatterns: [
      { pattern: /android:usesCleartextTraffic="true"/, message: "Cleartext HTTP traffic allowed" },
      { pattern: /cleartextTrafficPermitted="true"/, message: "Cleartext traffic permitted in network security config" },
    ],
  },
  {
    id: "AND-003",
    name: "Backup enabled (leaks encrypted DB)",
    description: "Android auto-backup can exfiltrate SQLCipher DB to Google Drive in plaintext",
    severity: "high",
    category: "Android",
    filePatterns: ["**/AndroidManifest.xml"],
    badPatterns: [
      { pattern: /android:allowBackup="true"/, message: "Auto-backup enabled — encrypted DB may be exfiltrated" },
    ],
  },
  {
    id: "AND-004",
    name: "SQLCipher key from Keystore without StrongBox",
    description: "SQLCipher key should use StrongBox-backed Keystore when available (hardware isolation)",
    severity: "medium",
    category: "Android",
    filePatterns: ["**/*.kt", "**/*.java"],
    badPatterns: [
      { pattern: /KeyGenParameterSpec[\s\S]{0,500}(?!setIsStrongBoxBacked).*\.build\(\)/, message: "KeyGenParameterSpec without StrongBox backing" },
    ],
  },
  {
    id: "AND-005",
    name: "WebView JavaScript enabled",
    description: "WebView with JS enabled can be exploited for XSS / code execution",
    severity: "medium",
    category: "Android",
    filePatterns: ["**/*.kt", "**/*.java"],
    badPatterns: [
      { pattern: /javaScriptEnabled\s*=\s*true|setJavaScriptEnabled\(true\)/, message: "WebView JavaScript enabled — XSS risk" },
    ],
  },
  {
    id: "AND-006",
    name: "Screenshot not blocked in sensitive screens",
    description: "Chat and PIN screens should set FLAG_SECURE to prevent screenshots/screen recording",
    severity: "low",
    category: "Android",
    filePatterns: ["**/*.kt", "**/*.java"],
    requiredPatterns: [
      { pattern: /FLAG_SECURE/, message: "No FLAG_SECURE found — sensitive screens can be screenshotted", filePattern: "**/*Activity*" },
    ],
  },
];

// ─── Rust Backend ───────────────────────────────────────────────

export const backendRules: Rule[] = [
  {
    id: "SRV-001",
    name: "Missing rate limiting on public endpoint",
    description: "Public-facing endpoints that modify data must have rate limiting",
    severity: "medium",
    category: "Backend",
    filePatterns: ["**/handlers/*.rs"],
    badPatterns: [
      { pattern: /async fn (?:register|login|send_sealed|create|upload)\w*\([^)]*\)[^{]*\{(?![\s\S]{0,300}rate_limiter)/, message: "Public write endpoint without rate limiting" },
    ],
  },
  {
    id: "SRV-002",
    name: "DashMap Ref held across .await",
    description: "Holding a DashMap Ref across an await point can deadlock",
    severity: "high",
    category: "Backend",
    filePatterns: ["**/*.rs"],
    badPatterns: [
      { pattern: /\.get\(&[\w]+\)[\s\S]{0,100}\.await(?![\s\S]{0,20}\.clone\(\))/, message: "DashMap Ref possibly held across .await — clone before awaiting" },
    ],
  },
  {
    id: "SRV-003",
    name: "SQL injection via string interpolation",
    description: "SQL queries must use parameterized queries, not string interpolation",
    severity: "critical",
    category: "Backend",
    filePatterns: ["**/*.rs"],
    badPatterns: [
      { pattern: /format!\(.*(?:SELECT|INSERT|UPDATE|DELETE).*\{/, message: "SQL query built with format! — use parameterized queries" },
      { pattern: /&format!\(".*(?:SELECT|INSERT|UPDATE|DELETE)/, message: "SQL query built with format!" },
    ],
  },
  {
    id: "SRV-004",
    name: "Missing auth middleware on route",
    description: "API routes handling user data must require authentication",
    severity: "high",
    category: "Backend",
    filePatterns: ["**/*.rs"],
    badPatterns: [
      { pattern: /\.route\("[^"]*(?:message|contact|vault|profile|session)[^"]*",\s*(?:get|post|put|delete)\(\w+\)\)(?![\s\S]{0,100}AuthUser)/, message: "Route handling sensitive data may lack auth middleware" },
    ],
  },
  {
    id: "SRV-005",
    name: "Secrets in error response",
    description: "Error responses must not leak internal state, stack traces, or secrets",
    severity: "medium",
    category: "Backend",
    filePatterns: ["**/*.rs"],
    badPatterns: [
      { pattern: /AppError::Internal\(format!\(.*(?:password|key|secret|token)/, message: "Error response may leak secrets" },
    ],
  },
  {
    id: "SRV-006",
    name: "CORS allows wildcard origin",
    description: "CORS must not allow all origins — limits CSRF protection",
    severity: "high",
    category: "Backend",
    filePatterns: ["**/*.rs"],
    badPatterns: [
      { pattern: /allow_origin\(.*Any|AllowOrigin::any\(\)|"\*"/, message: "CORS allows wildcard origin" },
    ],
  },
  {
    id: "SRV-007",
    name: "Unsafe Rust block outside FFI",
    description: "Unsafe blocks outside known FFI bindings need manual review",
    severity: "medium",
    category: "Backend",
    filePatterns: ["**/handlers/*.rs", "**/services/*.rs", "**/middleware/*.rs", "**/db/*.rs"],
    badPatterns: [
      { pattern: /unsafe\s*\{/, message: "Unsafe block in application code — verify memory safety" },
    ],
  },
];

// ─── Injection ──────────────────────────────────────────────────

export const injectionRules: Rule[] = [
  {
    id: "INJ-001",
    name: "SQL injection via string concatenation (JS/TS)",
    description: "SQL queries built with string concatenation or template literals allow SQL injection",
    severity: "critical",
    category: "Injection",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.mjs", "**/*.cjs"],
    badPatterns: [
      { pattern: /(?:query|execute|raw)\(\s*[`"'](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)[\s\S]{0,100}\$\{/, message: "SQL query built with template literal interpolation" },
      { pattern: /(?:query|execute|raw)\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,100}\+\s*(?:req\.|params\.|query\.|body\.|input|user)/, message: "SQL query concatenated with user input" },
    ],
  },
  {
    id: "INJ-002",
    name: "SQL injection via string formatting (Python)",
    description: "SQL queries built with f-strings or % formatting allow SQL injection",
    severity: "critical",
    category: "Injection",
    filePatterns: ["**/*.py"],
    badPatterns: [
      { pattern: /(?:execute|executemany|cursor\.execute)\(\s*f["'](?:SELECT|INSERT|UPDATE|DELETE)/, message: "SQL query built with Python f-string" },
      { pattern: /(?:execute|cursor\.execute)\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)[^"']*%s?["']\s*%\s*(?!tuple|\()/, message: "SQL query built with percent formatting — use parameterized queries" },
      { pattern: /(?:execute|cursor\.execute)\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\.\s*format\(/, message: "SQL query built with .format() — use parameterized queries" },
    ],
  },
  {
    id: "INJ-003",
    name: "SQL injection via string concatenation (Go)",
    description: "SQL queries built with fmt.Sprintf or concatenation allow SQL injection",
    severity: "critical",
    category: "Injection",
    filePatterns: ["**/*.go"],
    badPatterns: [
      { pattern: /fmt\.Sprintf\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE|DROP)/, message: "SQL query built with fmt.Sprintf — use parameterized queries" },
      { pattern: /(?:Query|Exec|QueryRow)\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\+/, message: "SQL query concatenated with variable" },
    ],
  },
  {
    id: "INJ-004",
    name: "SQL injection via string concatenation (Java)",
    description: "SQL queries built with string concatenation allow SQL injection",
    severity: "critical",
    category: "Injection",
    filePatterns: ["**/*.java", "**/*.kt"],
    badPatterns: [
      { pattern: /(?:createStatement|prepareStatement|executeQuery|executeUpdate)\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\+/, message: "SQL query concatenated with variable — use PreparedStatement" },
      { pattern: /(?:Statement|Connection)[\s\S]{0,50}\.(?:execute|executeQuery)\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,80}\+/, message: "JDBC Statement with string concatenation" },
    ],
  },
  {
    id: "INJ-005",
    name: "SQL injection via string concatenation (Ruby/PHP)",
    description: "SQL queries built with string interpolation allow SQL injection",
    severity: "critical",
    category: "Injection",
    filePatterns: ["**/*.rb", "**/*.php"],
    badPatterns: [
      { pattern: /(?:where|find_by_sql|execute)\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)[^"']*#\{/, message: "Ruby: SQL query with string interpolation" },
      { pattern: /(?:query|execute|prepare)\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)[^"']*\$(?:_GET|_POST|_REQUEST)/, message: "PHP: SQL query with superglobal variable" },
      { pattern: /(?:query|execute)\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\.\s*\$/, message: "PHP: SQL query concatenated with variable" },
    ],
  },
  {
    id: "INJ-006",
    name: "NoSQL injection",
    description: "NoSQL queries with unsanitized user input allow query manipulation",
    severity: "high",
    category: "Injection",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py"],
    badPatterns: [
      { pattern: /\.\s*find\(\s*\{[\s\S]{0,50}(?:req\.body|req\.query|req\.params|request\.)/, message: "MongoDB query with direct user input — risk of NoSQL injection" },
      { pattern: /\$where\s*:/, message: "MongoDB $where operator allows JavaScript code in queries" },
    ],
  },
  {
    id: "INJ-007",
    name: "OS command injection",
    description: "Running shell commands with user-controlled input allows arbitrary command running",
    severity: "critical",
    category: "Injection",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java", "**/*.rb", "**/*.php"],
    badPatterns: [
      { pattern: /child_process.*(?:req\.|params\.|query\.|body\.|input|user)/, message: "Node child_process with user input — OS command injection" },
      { pattern: /os\.system\(\s*f?["'].*(?:\{|%s|\+\s*\w)/, message: "Python os.system with dynamic input" },
      { pattern: /subprocess\.(?:call|run|Popen)\(\s*f?["'].*(?:\{|%s)/, message: "Python subprocess with string interpolation — use list form" },
      { pattern: /Runtime\.getRuntime\(\)/, message: "Java Runtime.getRuntime — verify no user input reaches command" },
    ],
  },
  {
    id: "INJ-008",
    name: "LDAP injection",
    description: "LDAP queries with unsanitized input allow filter manipulation",
    severity: "high",
    category: "Injection",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.java", "**/*.go"],
    badPatterns: [
      { pattern: /(?:ldap|LDAP)[\s\S]{0,100}(?:search|filter)[\s\S]{0,100}(?:\$\{|%s|\+\s*(?:req\.|user|input|param))/, message: "LDAP query with unsanitized input" },
    ],
  },
  {
    id: "INJ-009",
    name: "XPath injection",
    description: "XPath queries built with string concatenation allow injection",
    severity: "high",
    category: "Injection",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.java", "**/*.php"],
    badPatterns: [
      { pattern: /(?:xpath|XPath|evaluate)\(\s*["'].*(?:\$\{|\+\s*(?:req\.|user|input|param)|%s|\.format\()/, message: "XPath query with dynamic input — risk of XPath injection" },
    ],
  },
  {
    id: "INJ-010",
    name: "Header injection / CRLF injection",
    description: "Setting HTTP headers with unsanitized input allows response splitting",
    severity: "high",
    category: "Injection",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java", "**/*.rb", "**/*.php"],
    badPatterns: [
      { pattern: /(?:setHeader|set_header|Header\.Set|header)\(\s*["'][^"']+["'],\s*(?:req\.|params\.|query\.|body\.|input|user)/, message: "HTTP header set with user input — CRLF injection risk" },
    ],
  },
];

// ─── XSS (Cross-Site Scripting) ─────────────────────────────────

export const xssRules: Rule[] = [
  {
    id: "XSS-001",
    name: "innerHTML assignment with dynamic content",
    description: "Setting innerHTML with dynamic content allows script injection",
    severity: "high",
    category: "XSS",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.tsx", "**/*.jsx"],
    badPatterns: [
      { pattern: /\.innerHTML\s*=\s*(?!['"][^'"]*['"])/, message: "innerHTML assigned with dynamic value — XSS risk" },
      { pattern: /\.outerHTML\s*=\s*(?!['"][^'"]*['"])/, message: "outerHTML assigned with dynamic value — XSS risk" },
    ],
  },
  {
    id: "XSS-002",
    name: "DOM write methods with dynamic content",
    description: "document.write and document.writeln can run injected scripts",
    severity: "high",
    category: "XSS",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.tsx", "**/*.jsx", "**/*.html"],
    badPatterns: [
      { pattern: /document\.write(?:ln)?\((?!['"][^'"]*['"]\))/, message: "document.write with dynamic content — XSS risk" },
    ],
  },
  {
    id: "XSS-003",
    name: "React unsafe HTML rendering",
    description: "Using dangerouslySetInnerHTML bypasses React XSS protections",
    severity: "high",
    category: "XSS",
    filePatterns: ["**/*.tsx", "**/*.jsx", "**/*.ts", "**/*.js"],
    badPatterns: [
      { pattern: /dangerouslySetInnerHTML/, message: "React unsafe HTML rendering — verify input is sanitized" },
    ],
  },
  {
    id: "XSS-004",
    name: "Vue v-html directive",
    description: "v-html renders raw HTML and can run injected scripts",
    severity: "high",
    category: "XSS",
    filePatterns: ["**/*.vue", "**/*.ts", "**/*.js"],
    badPatterns: [
      { pattern: /v-html\s*=/, message: "Vue v-html renders raw HTML — XSS risk" },
    ],
  },
  {
    id: "XSS-005",
    name: "Angular bypassSecurityTrust",
    description: "Bypassing Angular sanitization exposes the app to XSS",
    severity: "high",
    category: "XSS",
    filePatterns: ["**/*.ts", "**/*.js"],
    badPatterns: [
      { pattern: /bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)/, message: "Angular security bypass — XSS risk" },
    ],
  },
  {
    id: "XSS-006",
    name: "Template injection via server-side rendering",
    description: "Passing unsanitized input to template engines can lead to SSTI or XSS",
    severity: "high",
    category: "XSS",
    filePatterns: ["**/*.py", "**/*.rb", "**/*.php", "**/*.ts", "**/*.js"],
    badPatterns: [
      { pattern: /\|safe\}|mark_safe\(|Markup\(|raw\s*%>|html_safe/, message: "Template rendering with safe/raw marker — verify input is sanitized" },
      { pattern: /render_template_string\(/, message: "Python: render_template_string allows SSTI" },
    ],
  },
  {
    id: "XSS-007",
    name: "jQuery HTML manipulation with dynamic content",
    description: "jQuery HTML methods with unsanitized input allow XSS",
    severity: "high",
    category: "XSS",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.html"],
    badPatterns: [
      { pattern: /\$\(.*\)\.(?:html|append|prepend|after|before)\(\s*(?!['"][^'"]*['"]\))/, message: "jQuery HTML manipulation with dynamic content — XSS risk" },
    ],
  },
  {
    id: "XSS-008",
    name: "Code evaluation with dynamic input",
    description: "Dynamic code evaluation constructs run arbitrary code if input is user-controlled",
    severity: "critical",
    category: "XSS",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.tsx", "**/*.jsx"],
    badPatterns: [
      { pattern: /\beval\s*\(\s*(?!['"][^'"]*['"]\))/, message: "Dynamic code evaluation with non-literal input — code injection risk" },
      { pattern: /setTimeout\(\s*["'`]/, message: "setTimeout with string argument — code injection risk, use function" },
      { pattern: /setInterval\(\s*["'`]/, message: "setInterval with string argument — code injection risk, use function" },
    ],
  },
];

// ─── Authentication / Authorization ─────────────────────────────

export const authRules: Rule[] = [
  {
    id: "AUTH-001",
    name: "Hardcoded JWT secret",
    description: "JWT signing secrets must not be hardcoded — use environment variables or key management",
    severity: "critical",
    category: "Authentication",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java", "**/*.rb", "**/*.php"],
    badPatterns: [
      { pattern: /(?:jwt|JWT)[\s\S]{0,50}(?:secret|key)\s*[:=]\s*["'][^"']{8,}["']/, message: "Hardcoded JWT secret" },
      { pattern: /sign\(\s*\{[\s\S]{0,200}["'][A-Za-z0-9+/=]{16,}["']/, message: "JWT signed with hardcoded secret string" },
    ],
  },
  {
    id: "AUTH-002",
    name: "JWT algorithm none accepted",
    description: "Accepting algorithm 'none' in JWT allows forging tokens without a key",
    severity: "critical",
    category: "Authentication",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java", "**/*.rb", "**/*.php"],
    badPatterns: [
      { pattern: /algorithm[s]?\s*[:=]\s*\[?["']none["']/, message: "JWT algorithm 'none' accepted — token forgery possible" },
      { pattern: /algorithms\s*[:=]\s*\[[\s\S]{0,100}["']none["']/, message: "JWT algorithm list includes 'none'" },
    ],
  },
  {
    id: "AUTH-003",
    name: "Missing JWT expiration",
    description: "JWTs without expiration never become invalid — stolen tokens work forever",
    severity: "high",
    category: "Authentication",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java"],
    badPatterns: [
      { pattern: /jwt\.sign\(\s*\{(?![\s\S]{0,300}(?:exp|expiresIn|expires_in))[\s\S]{0,300}\}/, message: "JWT signed without expiration claim" },
    ],
  },
  {
    id: "AUTH-004",
    name: "Weak password hashing (MD5/SHA1)",
    description: "MD5 and SHA1 are too fast for password hashing — use bcrypt, scrypt, or Argon2",
    severity: "critical",
    category: "Authentication",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java", "**/*.rb", "**/*.php"],
    badPatterns: [
      { pattern: /(?:md5|MD5|sha1|SHA1)\(.*(?:password|passwd|pwd)/i, message: "Password hashed with MD5/SHA1 — use bcrypt/scrypt/argon2" },
      { pattern: /(?:createHash|MessageDigest\.getInstance)\(\s*["'](?:md5|sha1|sha-1|MD5|SHA1|SHA-1)["']\)[\s\S]{0,200}(?:password|passwd|pwd)/i, message: "Weak hash algorithm used for passwords" },
      { pattern: /hashlib\.(?:md5|sha1)\(.*(?:password|passwd|pwd)/i, message: "Python: weak hash for password" },
    ],
  },
  {
    id: "AUTH-005",
    name: "Hardcoded password or credentials",
    description: "Passwords and credentials must not be hardcoded in source code",
    severity: "critical",
    category: "Authentication",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java", "**/*.rb", "**/*.php"],
    badPatterns: [
      { pattern: /(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{6,}["'](?!\s*(?:\|\||&&|if|==|!=|:))/, message: "Hardcoded password in source code" },
    ],
  },
  {
    id: "AUTH-006",
    name: "Missing authentication middleware",
    description: "Routes handling sensitive data must require authentication",
    severity: "high",
    category: "Authentication",
    filePatterns: ["**/*.ts", "**/*.js"],
    badPatterns: [
      { pattern: /(?:app|router)\.\s*(?:get|post|put|delete|patch)\(\s*['"]\/(?:api|admin|user|account|profile|settings|dashboard)[^'"]*['"][\s\S]{0,50}(?:req,\s*res)(?![\s\S]{0,200}(?:auth|authenticate|isAuthenticated|requireAuth|protect|verifyToken|isLoggedIn|session))/, message: "Route may lack authentication middleware" },
    ],
  },
  {
    id: "AUTH-007",
    name: "Session fixation vulnerability",
    description: "Session ID must be regenerated after authentication to prevent session fixation",
    severity: "high",
    category: "Authentication",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.java", "**/*.php"],
    badPatterns: [
      { pattern: /(?:login|authenticate|signIn)[\s\S]{0,500}(?:session\[|req\.session\.)(?![\s\S]{0,200}(?:regenerate|rotate|destroy))/, message: "Session not regenerated after login — session fixation risk" },
    ],
  },
  {
    id: "AUTH-008",
    name: "Timing-unsafe password comparison",
    description: "Comparing passwords or tokens with == allows timing attacks",
    severity: "high",
    category: "Authentication",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java", "**/*.rb", "**/*.php"],
    badPatterns: [
      { pattern: /(?:password|token|secret|apiKey|api_key)\s*(?:===?|!==?)\s*(?:req\.|params\.|body\.|input|user)/, message: "Timing-unsafe comparison of secret value — use constant-time compare" },
    ],
  },
];

// ─── Secrets / Credentials Exposure ─────────────────────────────

export const secretsRules: Rule[] = [
  {
    id: "SEC-001",
    name: "AWS access key in source",
    description: "AWS access keys in source code can be harvested by attackers for account compromise",
    severity: "critical",
    category: "Secrets",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java", "**/*.rb", "**/*.php", "**/*.env", "**/*.yml", "**/*.yaml", "**/*.json"],
    badPatterns: [
      { pattern: /AKIA[0-9A-Z]{16}/, message: "AWS access key ID found (AKIA...)" },
    ],
  },
  {
    id: "SEC-002",
    name: "AWS secret key in source",
    description: "AWS secret access keys must be stored in secure vaults, not source code",
    severity: "critical",
    category: "Secrets",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java", "**/*.rb", "**/*.php", "**/*.env", "**/*.yml", "**/*.yaml"],
    badPatterns: [
      { pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|SecretAccessKey)\s*[:=]\s*["'][A-Za-z0-9/+=]{40}["']/, message: "AWS secret access key found" },
    ],
  },
  {
    id: "SEC-003",
    name: "Generic API key pattern",
    description: "API keys in source code should be moved to environment variables or secret management",
    severity: "high",
    category: "Secrets",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java", "**/*.rb", "**/*.php"],
    badPatterns: [
      { pattern: /(?:api[_-]?key|apiKey|API_KEY)\s*[:=]\s*["'][A-Za-z0-9_\-]{20,}["']/, message: "API key hardcoded in source" },
    ],
  },
  {
    id: "SEC-004",
    name: "Private key in source",
    description: "Private keys embedded in source code compromise the entire cryptosystem",
    severity: "critical",
    category: "Secrets",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java", "**/*.rb", "**/*.php", "**/*.pem", "**/*.key"],
    badPatterns: [
      { pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/, message: "Private key found in source file" },
      { pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/, message: "PGP private key found in source file" },
    ],
  },
  {
    id: "SEC-005",
    name: "Hardcoded password in connection string",
    description: "Database connection strings with embedded passwords leak credentials if code is exposed",
    severity: "critical",
    category: "Secrets",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java", "**/*.rb", "**/*.php", "**/*.env", "**/*.yml", "**/*.yaml"],
    badPatterns: [
      { pattern: /(?:mysql|postgres|postgresql|mongodb|redis|amqp|mssql):\/\/\w+:[^@\s]{3,}@/, message: "Database connection string with embedded password" },
    ],
  },
  {
    id: "SEC-006",
    name: "GitHub token in source",
    description: "GitHub personal access tokens and app tokens must not be stored in source code",
    severity: "critical",
    category: "Secrets",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java", "**/*.rb", "**/*.php", "**/*.env", "**/*.yml", "**/*.yaml"],
    badPatterns: [
      { pattern: /ghp_[A-Za-z0-9]{36}/, message: "GitHub personal access token found" },
      { pattern: /gho_[A-Za-z0-9]{36}/, message: "GitHub OAuth token found" },
      { pattern: /ghs_[A-Za-z0-9]{36}/, message: "GitHub app installation token found" },
      { pattern: /ghr_[A-Za-z0-9]{36}/, message: "GitHub refresh token found" },
    ],
  },
  {
    id: "SEC-007",
    name: "Bearer token hardcoded",
    description: "Hardcoded bearer tokens in source code should be externalized",
    severity: "high",
    category: "Secrets",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java", "**/*.rb", "**/*.php"],
    badPatterns: [
      { pattern: /[Bb]earer\s+[A-Za-z0-9_\-\.]{20,}/, message: "Hardcoded bearer token found" },
      { pattern: /(?:Authorization|authorization)\s*[:=]\s*["']Bearer\s+[A-Za-z0-9_\-\.]{20,}["']/, message: "Hardcoded Authorization header with bearer token" },
    ],
  },
  {
    id: "SEC-008",
    name: "Slack/Discord webhook URL in source",
    description: "Webhook URLs contain embedded tokens and should be externalized",
    severity: "high",
    category: "Secrets",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java", "**/*.rb", "**/*.php"],
    badPatterns: [
      { pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/, message: "Slack webhook URL with token found" },
      { pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/, message: "Discord webhook URL with token found" },
    ],
  },
  {
    id: "SEC-009",
    name: "Google/GCP API key or service account key",
    description: "Google Cloud credentials must not be stored in source code",
    severity: "critical",
    category: "Secrets",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java", "**/*.json", "**/*.yml", "**/*.yaml"],
    badPatterns: [
      { pattern: /AIza[0-9A-Za-z_-]{35}/, message: "Google API key found" },
      { pattern: /"type"\s*:\s*"service_account"[\s\S]{0,200}"private_key"/, message: "GCP service account key found in source" },
    ],
  },
  {
    id: "SEC-010",
    name: "Stripe/payment API key in source",
    description: "Payment API keys must be stored securely — leaks lead to financial fraud",
    severity: "critical",
    category: "Secrets",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java", "**/*.rb", "**/*.php"],
    badPatterns: [
      { pattern: /sk_live_[0-9a-zA-Z]{24,}/, message: "Stripe live secret key found" },
      { pattern: /sk_test_[0-9a-zA-Z]{24,}/, message: "Stripe test secret key found — may still expose account" },
    ],
  },
];

// ─── SSRF / CSRF / Open Redirect ────────────────────────────────

export const ssrfCsrfRules: Rule[] = [
  {
    id: "NET-001",
    name: "Server-Side Request Forgery (SSRF)",
    description: "Fetching URLs from user input without validation allows SSRF attacks against internal services",
    severity: "high",
    category: "SSRF/CSRF",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java", "**/*.rb", "**/*.php"],
    badPatterns: [
      { pattern: /(?:fetch|axios|request|got|urllib|http\.Get|HttpClient)\(\s*(?:req\.|params\.|query\.|body\.|input|user)/, message: "URL fetched from user input — SSRF risk" },
      { pattern: /(?:fetch|axios\.get|requests\.get|http\.Get)\(\s*[`"'].*\$\{(?:req\.|params\.|query\.|body\.)/, message: "URL constructed from user input — SSRF risk" },
    ],
  },
  {
    id: "NET-002",
    name: "Missing CSRF token validation",
    description: "State-changing endpoints must validate CSRF tokens to prevent cross-site request forgery",
    severity: "high",
    category: "SSRF/CSRF",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.java", "**/*.php"],
    badPatterns: [
      { pattern: /(?:app|router)\.\s*(?:post|put|delete|patch)\([\s\S]{0,200}(?:req,\s*res)(?![\s\S]{0,200}(?:csrf|CSRF|csrfToken|_csrf|xsrf|XSRF))/, message: "State-changing endpoint may lack CSRF protection" },
    ],
  },
  {
    id: "NET-003",
    name: "Open redirect",
    description: "Redirecting to user-controlled URLs allows phishing attacks",
    severity: "medium",
    category: "SSRF/CSRF",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java", "**/*.rb", "**/*.php"],
    badPatterns: [
      { pattern: /(?:redirect|res\.redirect|Response\.Redirect|sendRedirect|header\(\s*["']Location)\s*\(\s*(?:req\.|params\.|query\.|body\.|input|request\.)/, message: "Redirect to user-controlled URL — open redirect risk" },
      { pattern: /(?:redirect|sendRedirect|Location)\s*\(\s*(?:req\.query|req\.params|request\.GET|request\.args)\[?\s*["'](?:url|redirect|next|return|goto|target|dest|destination)/, message: "Redirect target from user parameter — open redirect risk" },
    ],
  },
  {
    id: "NET-004",
    name: "Unvalidated file URL/path from user input",
    description: "Reading files from user-specified paths allows path traversal attacks",
    severity: "high",
    category: "SSRF/CSRF",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java", "**/*.rb", "**/*.php"],
    badPatterns: [
      { pattern: /(?:readFile|readFileSync|open|fopen|FileReader)\(\s*(?:req\.|params\.|query\.|body\.|input|user)/, message: "File read with user-controlled path — path traversal risk" },
    ],
  },
  {
    id: "NET-005",
    name: "Missing Content-Security-Policy header",
    description: "CSP header prevents XSS, clickjacking, and other injection attacks",
    severity: "medium",
    category: "SSRF/CSRF",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py"],
    requiredPatterns: [
      { pattern: /content-security-policy|Content-Security-Policy|CSP|helmet|csp/i, message: "No Content-Security-Policy header configuration found", filePattern: "**/server*" },
    ],
  },
  {
    id: "NET-006",
    name: "DNS rebinding vulnerability",
    description: "URL validation at request time can be bypassed by DNS rebinding if not re-checked at connection time",
    severity: "high",
    category: "SSRF/CSRF",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java"],
    badPatterns: [
      { pattern: /(?:new\s+URL|url\.parse|URL\.parse)\([\s\S]{0,100}(?:hostname|host)[\s\S]{0,100}(?:fetch|request|get|http)/, message: "URL validated then fetched separately — DNS rebinding risk" },
    ],
  },
];

// ─── Memory Safety (C/C++/Rust) ─────────────────────────────────

export const memorySafetyRules: Rule[] = [
  {
    id: "MEM-001",
    name: "strcpy buffer overflow",
    description: "strcpy does not check buffer bounds — use strncpy or strlcpy",
    severity: "critical",
    category: "Memory Safety",
    filePatterns: ["**/*.c", "**/*.cpp", "**/*.h", "**/*.hpp"],
    badPatterns: [
      { pattern: /\bstrcpy\s*\(/, message: "strcpy used — no bounds checking, buffer overflow risk" },
      { pattern: /\bstrcat\s*\(/, message: "strcat used — no bounds checking, buffer overflow risk" },
    ],
  },
  {
    id: "MEM-002",
    name: "sprintf buffer overflow",
    description: "sprintf does not check buffer bounds — use snprintf",
    severity: "critical",
    category: "Memory Safety",
    filePatterns: ["**/*.c", "**/*.cpp", "**/*.h", "**/*.hpp"],
    badPatterns: [
      { pattern: /\bsprintf\s*\(/, message: "sprintf used — no bounds checking, use snprintf" },
      { pattern: /\bvsprintf\s*\(/, message: "vsprintf used — no bounds checking, use vsnprintf" },
    ],
  },
  {
    id: "MEM-003",
    name: "gets() — always unsafe",
    description: "gets() cannot limit input size and always causes buffer overflow potential — use fgets()",
    severity: "critical",
    category: "Memory Safety",
    filePatterns: ["**/*.c", "**/*.cpp", "**/*.h", "**/*.hpp"],
    badPatterns: [
      { pattern: /\bgets\s*\(/, message: "gets() is always unsafe — use fgets()" },
    ],
  },
  {
    id: "MEM-004",
    name: "Format string vulnerability",
    description: "Printf-family functions with user-controlled format strings allow memory read/write",
    severity: "critical",
    category: "Memory Safety",
    filePatterns: ["**/*.c", "**/*.cpp", "**/*.h", "**/*.hpp"],
    badPatterns: [
      { pattern: /printf\(\s*(?:buf|buffer|input|user|str|data|msg|argv)\w*\s*\)/, message: "printf with variable as format string — use explicit format specifier" },
      { pattern: /fprintf\(\s*\w+\s*,\s*(?:buf|buffer|input|user|str|data|msg)\w*\s*\)/, message: "fprintf with variable as format string" },
      { pattern: /syslog\(\s*\w+\s*,\s*(?:buf|buffer|input|user|str|data|msg)\w*\s*\)/, message: "syslog with variable as format string" },
    ],
  },
  {
    id: "MEM-005",
    name: "Rust unsafe block",
    description: "Unsafe blocks bypass Rust memory safety guarantees — each one needs careful review",
    severity: "medium",
    category: "Memory Safety",
    filePatterns: ["**/*.rs"],
    badPatterns: [
      { pattern: /unsafe\s*\{/, message: "Unsafe block — verify memory safety manually" },
    ],
  },
  {
    id: "MEM-006",
    name: "Use-after-free pattern (C/C++)",
    description: "Using a pointer after free() leads to undefined behavior and potential exploitation",
    severity: "critical",
    category: "Memory Safety",
    filePatterns: ["**/*.c", "**/*.cpp", "**/*.h", "**/*.hpp"],
    badPatterns: [
      { pattern: /free\(\s*(\w+)\s*\)\s*;(?![\s\S]{0,20}\1\s*=\s*NULL)/, message: "Pointer not set to NULL after free — use-after-free risk" },
    ],
  },
  {
    id: "MEM-007",
    name: "Integer overflow in allocation",
    description: "Unchecked integer arithmetic in malloc/calloc size can cause heap overflow",
    severity: "high",
    category: "Memory Safety",
    filePatterns: ["**/*.c", "**/*.cpp", "**/*.h", "**/*.hpp"],
    badPatterns: [
      { pattern: /malloc\(\s*\w+\s*\*\s*\w+\s*\)/, message: "Multiplication in malloc size — integer overflow risk, use calloc or check overflow" },
    ],
  },
];

// ─── Concurrency / Race Conditions ──────────────────────────────

export const concurrencyRules: Rule[] = [
  {
    id: "RACE-001",
    name: "Check-then-act race condition (filesystem)",
    description: "Checking file existence then acting on it creates a TOCTOU race condition",
    severity: "high",
    category: "Concurrency",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.go", "**/*.java", "**/*.rb", "**/*.php", "**/*.c", "**/*.cpp"],
    badPatterns: [
      { pattern: /(?:existsSync|exists|access|stat)\([\s\S]{0,100}(?:writeFile|unlink|rename|readFile|open|createWriteStream)/, message: "TOCTOU: file existence check then file operation — race condition" },
      { pattern: /if\s*\(\s*(?:fs\.)?existsSync\(/, message: "Filesystem check-then-act pattern — consider using exclusive file flags instead" },
    ],
  },
  {
    id: "RACE-002",
    name: "Missing lock around shared state",
    description: "Concurrent access to shared mutable state without synchronization causes data races",
    severity: "high",
    category: "Concurrency",
    filePatterns: ["**/*.go"],
    badPatterns: [
      { pattern: /var\s+\w+\s+(?:map|slice|\[\])[\s\S]{0,500}go\s+func\(\)/, message: "Go: shared variable accessed from goroutine without mutex" },
    ],
  },
  {
    id: "RACE-003",
    name: "Fire-and-forget promise/async operation",
    description: "Unhandled promises or async operations silently swallow errors",
    severity: "medium",
    category: "Concurrency",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.tsx", "**/*.jsx"],
    badPatterns: [
      { pattern: /(?:^|\s)(?!return\s|await\s)(?:fetch|axios\.\w+|request)\([^)]*\)\s*;(?!\s*(?:\.then|\.catch))/, message: "Fire-and-forget async call — errors will be silently lost" },
    ],
  },
  {
    id: "RACE-004",
    name: "Missing error handler on promise",
    description: "Promises without .catch() or try/catch silently swallow rejections",
    severity: "medium",
    category: "Concurrency",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.tsx", "**/*.jsx"],
    badPatterns: [
      { pattern: /\.then\([^)]*\)\s*;(?!\s*\.catch)/, message: "Promise chain without .catch() — unhandled rejection risk" },
    ],
  },
  {
    id: "RACE-005",
    name: "Shared state modification in async handler without lock",
    description: "Modifying shared state in concurrent request handlers causes race conditions",
    severity: "high",
    category: "Concurrency",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py"],
    badPatterns: [
      { pattern: /(?:let|var)\s+\w+\s*=\s*(?:0|{|}|\[|\]|new Map|new Set)[\s\S]{0,300}(?:app|router)\.\s*(?:get|post|put|delete)\(/, message: "Module-level mutable variable near route handlers — race condition risk" },
    ],
  },
];

// ─── Dependency / Deserialization ────────────────────────────────

export const dependencyRules: Rule[] = [
  {
    id: "DEP-001",
    name: "Unsafe deserialization (Python pickle)",
    description: "pickle.loads with untrusted input allows arbitrary code running on the server",
    severity: "critical",
    category: "Deserialization",
    filePatterns: ["**/*.py"],
    badPatterns: [
      { pattern: /pickle\.loads?\(/, message: "Python pickle deserialization — RCE risk with untrusted input" },
      { pattern: /cPickle\.loads?\(/, message: "Python cPickle deserialization — RCE risk with untrusted input" },
      { pattern: /shelve\.open\(/, message: "Python shelve uses pickle internally — RCE risk with untrusted data" },
    ],
  },
  {
    id: "DEP-002",
    name: "Unsafe deserialization (Ruby Marshal)",
    description: "Marshal.load with untrusted input allows arbitrary code running",
    severity: "critical",
    category: "Deserialization",
    filePatterns: ["**/*.rb"],
    badPatterns: [
      { pattern: /Marshal\.load\(/, message: "Ruby Marshal.load — RCE risk with untrusted input" },
      { pattern: /YAML\.load\((?!.*safe)/, message: "Ruby YAML.load — RCE risk, use YAML.safe_load" },
    ],
  },
  {
    id: "DEP-003",
    name: "Unsafe deserialization (PHP unserialize)",
    description: "unserialize with untrusted input allows object injection and code running",
    severity: "critical",
    category: "Deserialization",
    filePatterns: ["**/*.php"],
    badPatterns: [
      { pattern: /\bunserialize\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|input)/, message: "PHP unserialize with user input — object injection risk" },
      { pattern: /\bunserialize\(/, message: "PHP unserialize — verify input is not user-controlled" },
    ],
  },
  {
    id: "DEP-004",
    name: "Unsafe deserialization (Java ObjectInputStream)",
    description: "Java ObjectInputStream.readObject with untrusted data allows arbitrary code running",
    severity: "critical",
    category: "Deserialization",
    filePatterns: ["**/*.java", "**/*.kt"],
    badPatterns: [
      { pattern: /ObjectInputStream[\s\S]{0,100}readObject\(\)/, message: "Java ObjectInputStream deserialization — RCE risk with untrusted input" },
      { pattern: /XMLDecoder[\s\S]{0,100}readObject\(\)/, message: "Java XMLDecoder deserialization — RCE risk" },
    ],
  },
  {
    id: "DEP-005",
    name: "Prototype pollution",
    description: "Merging user input into objects can modify Object.prototype and compromise the application",
    severity: "high",
    category: "Deserialization",
    filePatterns: ["**/*.ts", "**/*.js"],
    badPatterns: [
      { pattern: /Object\.assign\(\s*\{\}\s*,\s*(?:req\.|params\.|query\.|body\.|input|user)/, message: "Object.assign with user input — prototype pollution risk" },
      { pattern: /(?:lodash|_)\.merge\(\s*\{\}\s*,\s*(?:req\.|params\.|query\.|body\.|input|user)/, message: "Deep merge with user input — prototype pollution risk" },
      { pattern: /\[["']__proto__["']\]|__proto__/, message: "__proto__ access — prototype pollution risk" },
    ],
  },
  {
    id: "DEP-006",
    name: "Dynamic code from user input",
    description: "Evaluating dynamically constructed code from user input allows arbitrary code running",
    severity: "critical",
    category: "Deserialization",
    filePatterns: ["**/*.ts", "**/*.js", "**/*.py", "**/*.rb", "**/*.php"],
    badPatterns: [
      { pattern: /\beval\s*\(\s*(?:req\.|params\.|query\.|body\.|input|user)/, message: "Dynamic evaluation of user input — code injection" },
      { pattern: /\bvm\.runInNewContext\(/, message: "Node.js vm.runInNewContext — sandbox escape possible" },
    ],
  },
  {
    id: "DEP-007",
    name: "Unsafe YAML deserialization",
    description: "YAML.load/yaml.load without safe loader allows code running via crafted YAML",
    severity: "high",
    category: "Deserialization",
    filePatterns: ["**/*.py", "**/*.ts", "**/*.js"],
    badPatterns: [
      { pattern: /yaml\.load\(\s*(?!.*Loader\s*=\s*(?:yaml\.)?SafeLoader)/, message: "Python yaml.load without SafeLoader — code running risk" },
      { pattern: /yaml\.(?:unsafe_load|full_load)\(/, message: "Python unsafe YAML loading — code running risk" },
    ],
  },
];

export const allRules: Rule[] = [
  ...e2eRules,
  ...webrtcRules,
  ...messengerRules,
  ...androidRules,
  ...backendRules,
  ...injectionRules,
  ...xssRules,
  ...authRules,
  ...secretsRules,
  ...ssrfCsrfRules,
  ...memorySafetyRules,
  ...concurrencyRules,
  ...dependencyRules,
];
